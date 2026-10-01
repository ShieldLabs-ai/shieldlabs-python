#!/usr/bin/env python3
"""Sync the shared ShieldLabs API contract files into an SDK repository.

The contract lives in the public shieldlabs-openapi repository under contract/: shared test
fixtures plus contract/manifest.json, which lists the SHA-256 of every file. An SDK repository
says where each file goes in contract-sync.json:

    {"source": "shieldlabs-openapi",
     "files": {"normalization-cases.json": "tests/data/normalization-cases.json"}}

and records what it synced in .shieldlabs-contract.lock:

    {"ref": "v1.0.1", "contract_version": "1.0.1",
     "files": {"normalization-cases.json": "<sha256>"}}

Usage, from the repository root (Python 3.9 or later, standard library only):

    python3 scripts/sync_contract.py                 sync the newest vX.Y.Z tag
    python3 scripts/sync_contract.py --ref v1.0.1    sync one release
    python3 scripts/sync_contract.py --check         offline: committed files match the lock

The canonical copy of this script is scripts/sync_contract.py in shieldlabs-openapi. SDK
repositories keep an identical copy, so --check works offline.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Callable, Optional, TextIO, Union

DEFAULT_OWNER = "ShieldLabs-ai"
CONFIG_FILE = "contract-sync.json"
LOCK_FILE = ".shieldlabs-contract.lock"
MANIFEST_FILE = "manifest.json"
CONTRACT_DIR = "contract"
RAW_BASE = "https://raw.githubusercontent.com"
API_BASE = "https://api.github.com"
USER_AGENT = "shieldlabs-contract-sync"

REF_PATTERN = re.compile(r"latest|v[0-9]+\.[0-9]+\.[0-9]+")
TAG_PATTERN = re.compile(r"v([0-9]+)\.([0-9]+)\.([0-9]+)")
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SOURCE_PATTERN = re.compile(r"(?:[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="next"')

# (url, headers) -> (body, URL of the next page from the Link header, if any)
Fetch = Callable[[str, dict[str, str]], tuple[bytes, Optional[str]]]


class ContractError(Exception):
    """A problem to fix: bad input, a missing file, a hash mismatch or drift."""


class NotFoundError(ContractError):
    """The requested file does not exist."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_ref(ref: str) -> str:
    if not REF_PATTERN.fullmatch(ref):
        raise ContractError(f"invalid ref {ref!r}: use 'latest' or a tag such as v1.2.3")
    return ref


def validate_name(name: object) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or name == MANIFEST_FILE:
        raise ContractError(f"invalid contract file name {name!r}")
    return name


def validate_digests(files: dict, where: str) -> dict[str, str]:
    for name, digest in files.items():
        validate_name(name)
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ContractError(f"{where}: invalid SHA-256 for {name}")
    return files


def destination(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ContractError(f"invalid destination path {value!r}")
    rel = PurePosixPath(value)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise ContractError(f"destination must be a relative path inside the repository: {value!r}")
    return root.joinpath(*rel.parts)


def read_json(path: Path, what: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ContractError(f"{what} not found: {path}") from None
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError(f"{what} is not valid JSON: {path}: {exc}") from None


class Config:
    """contract-sync.json: the source repository and where each contract file goes."""

    def __init__(self, root: Path, owner: str, repo: str, files: dict[str, Path]) -> None:
        self.root = root
        self.owner = owner
        self.repo = repo
        self.files = files

    @classmethod
    def load(cls, root: Path, path: Path) -> "Config":
        data = read_json(path, CONFIG_FILE)
        if not isinstance(data, dict):
            raise ContractError(f"{path}: expected a JSON object")
        source = data.get("source")
        if not isinstance(source, str) or not SOURCE_PATTERN.fullmatch(source):
            raise ContractError(f"{path}: 'source' must be a repository such as shieldlabs-openapi")
        owner, _, repo = source.rpartition("/")
        files = data.get("files")
        if not isinstance(files, dict) or not files:
            raise ContractError(f"{path}: 'files' must map contract file names to paths")
        mapped: dict[str, Path] = {}
        for name, value in files.items():
            target = destination(root, value)
            if target in mapped.values():
                raise ContractError(f"{path}: two contract files map to {value}")
            mapped[validate_name(name)] = target
        return cls(root, owner or DEFAULT_OWNER, repo, mapped)

    def display(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()


def parse_manifest(data: bytes) -> tuple[str, dict[str, str]]:
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError(f"{MANIFEST_FILE} is not valid JSON: {exc}") from None
    if not isinstance(manifest, dict):
        raise ContractError(f"{MANIFEST_FILE}: expected a JSON object")
    version, files = manifest.get("contract_version"), manifest.get("files")
    if not isinstance(version, str) or not version or not isinstance(files, dict):
        raise ContractError(f"{MANIFEST_FILE} needs 'contract_version' and 'files'")
    return version, validate_digests(files, MANIFEST_FILE)


def load_lock(path: Path) -> tuple[str, str, dict[str, str]]:
    data = read_json(path, LOCK_FILE)
    if not isinstance(data, dict):
        raise ContractError(f"{path}: expected a JSON object")
    ref, version, files = data.get("ref"), data.get("contract_version"), data.get("files")
    if not isinstance(ref, str) or not TAG_PATTERN.fullmatch(ref):
        raise ContractError(f"{path}: 'ref' must be a tag such as v1.2.3")
    if not isinstance(version, str) or not isinstance(files, dict):
        raise ContractError(f"{path}: 'contract_version' and 'files' are required")
    return ref, version, validate_digests(files, str(path))


def render_lock(ref: str, version: str, files: dict[str, str]) -> str:
    lock = {"ref": ref, "contract_version": version, "files": dict(sorted(files.items()))}
    return json.dumps(lock, indent=2) + "\n"


def http_fetch(url: str, headers: dict[str, str]) -> tuple[bytes, Optional[str]]:
    """GET with a timeout; network errors and 5xx answers are retried twice."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    for attempt in range(3):
        if attempt:
            time.sleep(2**attempt)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                match = NEXT_LINK.search(response.headers.get("Link") or "")
                return response.read(), match.group(1) if match else None
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFoundError(f"not found: {url}") from None
            if exc.code < 500 or attempt == 2:
                raise ContractError(f"HTTP {exc.code} for {url}") from None
        except (urllib.error.URLError, OSError) as exc:
            if attempt == 2:
                raise ContractError(f"cannot fetch {url}: {exc}") from None
    raise ContractError(f"cannot fetch {url}")


def newest_tag(names: list[str]) -> Optional[str]:
    versions = []
    for name in names:
        match = TAG_PATTERN.fullmatch(name)
        if match:
            versions.append((tuple(int(part) for part in match.groups()), name))
    return max(versions)[1] if versions else None


def resolve_latest(owner: str, repo: str, fetch: Fetch = http_fetch) -> str:
    """The newest vX.Y.Z tag of owner/repo from the public GitHub API. No token is needed;
    GITHUB_TOKEN, when set, only raises the API rate limit."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url: Optional[str] = f"{API_BASE}/repos/{owner}/{repo}/tags?per_page=100"
    names: list[str] = []
    pages = 0
    while url and pages < 20:
        body, url = fetch(url, headers)
        pages += 1
        try:
            page = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ContractError(f"unexpected answer from the GitHub API: {exc}") from None
        if not isinstance(page, list):
            raise ContractError("unexpected answer from the GitHub API: expected a list of tags")
        names.extend(
            t["name"] for t in page if isinstance(t, dict) and isinstance(t.get("name"), str)
        )
    tag = newest_tag(names)
    if tag is None:
        raise ContractError(f"{owner}/{repo} has no vX.Y.Z tag yet")
    return tag


class RemoteSource:
    """Contract files of one tag, downloaded from raw.githubusercontent.com."""

    def __init__(self, owner: str, repo: str, ref: str, fetch: Fetch = http_fetch) -> None:
        self.base = f"{RAW_BASE}/{owner}/{repo}/{ref}/{CONTRACT_DIR}"
        self.ref = ref
        self.fetch = fetch

    def read(self, name: str) -> bytes:
        try:
            return self.fetch(f"{self.base}/{name}", {})[0]
        except NotFoundError:
            if name == MANIFEST_FILE:
                raise ContractError(
                    f"{self.ref} has no {CONTRACT_DIR}/{MANIFEST_FILE}: "
                    "that release predates the contract"
                ) from None
            raise


class LocalSource:
    """Contract files from a local directory, such as contract/ in a checkout."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def read(self, name: str) -> bytes:
        try:
            return (self.directory / name).read_bytes()
        except FileNotFoundError:
            raise NotFoundError(f"not found: {self.directory / name}") from None


Source = Union[RemoteSource, LocalSource]


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def sync(config: Config, source: Source, ref: str, lock: Path, out: TextIO) -> list[str]:
    """Downloads and verifies every mapped file, then writes the files and the lock.

    Nothing is written unless every file matches the manifest. Returns the changed paths."""
    version, manifest = parse_manifest(source.read(MANIFEST_FILE))
    missing = sorted(set(config.files) - set(manifest))
    if missing:
        raise ContractError(f"contract {ref} does not contain: {', '.join(missing)}")
    payloads: dict[str, bytes] = {}
    for name in sorted(config.files):
        data = source.read(name)
        digest = sha256_bytes(data)
        if digest != manifest[name]:
            raise ContractError(
                f"{name} at {ref} does not match {MANIFEST_FILE} "
                f"(expected {manifest[name][:12]}, got {digest[:12]}); nothing was written"
            )
        payloads[name] = data
    lock_bytes = render_lock(ref, version, {n: manifest[n] for n in payloads}).encode("utf-8")
    changed = []
    for path, data in [*((config.files[n], d) for n, d in payloads.items()), (lock, lock_bytes)]:
        if not path.is_file() or path.read_bytes() != data:
            write_atomic(path, data)
            changed.append(config.display(path))
    print(f"Contract {ref} (contract_version {version}): {len(payloads)} files", file=out)
    for path in changed:
        print(f"  updated {path}", file=out)
    if not changed:
        print("  already up to date", file=out)
    return changed


def check(config: Config, lock: Path, out: TextIO) -> list[str]:
    """Offline: compares the committed files with the lock. Returns one message per problem."""
    ref, version, locked = load_lock(lock)
    mapped, listed = set(config.files), set(locked)
    problems = [f"{n}: in {CONFIG_FILE} but not in the lock" for n in sorted(mapped - listed)]
    problems += [f"{n}: in the lock but not in {CONFIG_FILE}" for n in sorted(listed - mapped)]
    for name in sorted(mapped & listed):
        path = config.files[name]
        if not path.is_file():
            problems.append(f"{config.display(path)}: missing")
            continue
        digest = sha256_bytes(path.read_bytes())
        if digest != locked[name]:
            problems.append(
                f"{config.display(path)}: SHA-256 {digest[:12]} differs from the lock "
                f"({locked[name][:12]}, contract {ref})"
            )
    if not problems:
        print(
            f"Contract files match the lock: {ref}, "
            f"contract_version {version}, {len(locked)} files",
            file=out,
        )
    return problems


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sync the shared ShieldLabs API contract files into this repository."
    )
    parser.add_argument(
        "--ref", default="latest", help="'latest' (default) or a tag such as v1.2.3"
    )
    parser.add_argument(
        "--check", action="store_true", help="offline: compare the files with the lock"
    )
    parser.add_argument("--root", default=".", help="repository root (default: current directory)")
    parser.add_argument("--config", default=CONFIG_FILE, help="mapping file, relative to --root")
    parser.add_argument("--lock", default=LOCK_FILE, help="lock file, relative to --root")
    parser.add_argument(
        "--source-dir", help="read the contract from a local directory (needs a tag in --ref)"
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    try:
        config = Config.load(root, root / args.config)
        lock = root / args.lock
        if args.check:
            problems = check(config, lock, sys.stdout)
            if problems:
                print(f"Contract drift: these files do not match {args.lock}:", file=sys.stderr)
                for problem in problems:
                    print(f"  {problem}", file=sys.stderr)
                print(
                    "Contract files are not edited by hand. Change them in shieldlabs-openapi, or "
                    "restore them with: python3 scripts/sync_contract.py --ref <ref in the lock>",
                    file=sys.stderr,
                )
                return 1
            return 0
        ref = validate_ref(args.ref)
        source: Source
        if args.source_dir:
            if ref == "latest":
                raise ContractError("--source-dir needs a tag in --ref, such as v1.2.3")
            source = LocalSource(Path(args.source_dir))
        else:
            if ref == "latest":
                ref = resolve_latest(config.owner, config.repo)
            source = RemoteSource(config.owner, config.repo, ref)
        sync(config, source, ref, lock, sys.stdout)
        return 0
    except ContractError as exc:
        print(f"contract-sync: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
