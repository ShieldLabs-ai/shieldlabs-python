"""Prove regenerated breaking schemas fail against the real client source."""

from __future__ import annotations

import copy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=90)


def main() -> None:
    original = yaml.safe_load((ROOT / "resources/shieldlabs-api.yaml").read_text())
    # Mutate fields actually read by the supported client, never test-only typed literals.
    cases = [
        ("history score rename", "HistoryRow", "score", "rename"),
        ("history score type", "HistoryRow", "score", "string"),
        ("history total type", "HistoryPage", "total", "string"),
        ("profile Weight type", "DomainProfile", "Weight", "string"),
        ("profile Domain rename", "DomainProfile", "Domain", "rename"),
        ("webhook score type", "IdentificationScoredData", "risk_score", "string"),
        ("webhook flag type", "DetectionFlags", "vpn", "string"),
        ("webhook signal weight type", "Signal", "weight", "string"),
        ("webhook timestamp type", "IdentificationScoredEvent", "created_at", "integer"),
        ("ping timestamp type", "WebhookPingEvent", "created_at", "integer"),
        ("ping timestamp rename", "WebhookPingEvent", "created_at", "rename"),
        ("ping schema_version type", "WebhookPingEvent", "schema_version", "integer"),
        ("ping schema_version rename", "WebhookPingEvent", "schema_version", "rename"),
        ("query limit rename", "HistoryLimit", "name", "rename_parameter"),
        ("query limit type", "HistoryLimit", "schema", "parameter_type"),
        ("search type rename", "HistorySearchType", "name", "rename_parameter"),
        ("profile header rename", "ShieldDomain", "name", "rename_parameter"),
        ("query limit moved to header", "HistoryLimit", "in", "move_parameter"),
        ("profile header moved to query", "ShieldDomain", "in", "move_parameter"),
        ("local IP type", "IpInfo", "ip", "local_type"),
        ("local country type", "IpInfo", "country", "local_type"),
        ("ping discriminator rename", "WebhookPingEvent", "event_type", "rename"),
        ("ping discriminator type", "WebhookPingEvent", "event_type", "integer"),
    ]
    with tempfile.TemporaryDirectory(prefix=".wire-drift-", dir=ROOT) as directory:
        scratch = Path(directory)
        shutil.copytree(ROOT / "src", scratch / "src", ignore=shutil.ignore_patterns("__pycache__"))
        schema_path = scratch / "api.yaml"
        output = scratch / "src/shieldlabs/_generated_wire.py"

        def check(
            document: dict,
            label: str,
            should_pass: bool,
            rejects_required: bool = False,
            rejects_contract: Optional[str] = None,
        ) -> None:
            schema_path.write_text(yaml.safe_dump(document, sort_keys=False))
            generated = run(
                [
                    sys.executable,
                    "scripts/generate_wire.py",
                    "--schema",
                    str(schema_path),
                    "--output",
                    str(output),
                ]
            )
            if generated.returncode:
                if rejects_required and "Unsupported required parameter" in generated.stderr:
                    print(f"PASS {label}: generator rejects unsupported required parameter")
                    return
                if rejects_contract and rejects_contract in generated.stderr:
                    print(f"PASS {label}: generator rejects incompatible contract")
                    return
                raise RuntimeError(f"{label}: generation failed unexpectedly\n{generated.stderr}")
            if rejects_required:
                raise RuntimeError(f"{label}: generator accepted unsupported required parameter")
            if rejects_contract:
                raise RuntimeError(f"{label}: generator accepted incompatible contract")
            result = run(
                [
                    sys.executable,
                    "-m",
                    "mypy",
                    "--strict",
                    "--no-incremental",
                    "--cache-dir",
                    str(scratch / "cache"),
                    str(scratch / "src"),
                ]
            )
            if (result.returncode == 0) != should_pass:
                raise RuntimeError(
                    f"{label}: unexpected compile result\n{result.stdout}{result.stderr}"
                )
            if not should_pass and not any(
                name in result.stdout
                for name in (
                    "_models.py",
                    "_client.py",
                    "_management.py",
                    "webhooks.py",
                    "_validation.py",
                )
            ):
                raise RuntimeError(f"{label}: did not fail in a real SDK consumer\n{result.stdout}")
            print(f"PASS {label}: {'compiles' if should_pass else 'consumer rejects change'}")

        check(original, "baseline", True)
        for label, model, field, change in cases:
            document = copy.deepcopy(original)
            if change in ("rename_parameter", "parameter_type", "move_parameter"):
                parameter = document["components"]["parameters"][model]
                if change == "rename_parameter":
                    parameter["name"] += "_changed"
                elif change == "move_parameter":
                    parameter["in"] = "header" if parameter["in"] == "query" else "query"
                else:
                    parameter["schema"] = {"type": "string"}
            elif change == "local_type":
                local = copy.deepcopy(document["components"]["schemas"]["IpInfo"])
                local["properties"][field] = {"type": "integer"}
                document["components"]["schemas"]["IdentificationScoredData"]["properties"][
                    "local_ip"
                ] = local
            else:
                properties = document["components"]["schemas"][model]["properties"]
                if change == "rename":
                    properties[field + "_changed"] = properties.pop(field)
                else:
                    properties[field] = {"type": change}
            rejects_required = change in ("rename_parameter", "move_parameter") and model in (
                "HistorySearchType",
                "ShieldDomain",
            )
            rejects_contract = (
                "Unsupported webhook discriminator"
                if model == "WebhookPingEvent" and field == "event_type"
                else None
            )
            check(
                document,
                label,
                False,
                rejects_required=rejects_required,
                rejects_contract=rejects_contract,
            )
        document = copy.deepcopy(original)
        document["components"]["parameters"]["HistorySearchType"]["schema"]["enum"].append(
            "account_id"
        )
        check(document, "lookup enum addition", False, rejects_contract="Unsupported lookup types")
        for operation_id in ("searchHistory", "getDomainProfile"):
            document = copy.deepcopy(original)
            path = next(
                value
                for value in document["paths"].values()
                if value.get("get", {}).get("operationId") == operation_id
            )
            path["post"] = path.pop("get")
            check(
                document,
                f"{operation_id} GET to POST",
                False,
                rejects_contract="Unsupported HTTP method",
            )
        document = copy.deepcopy(original)
        document["components"]["schemas"]["HistoryRow"]["properties"]["new_optional_field"] = {
            "type": "string"
        }
        check(document, "optional additive field", True)
        for operation_id in ("searchHistory", "getDomainProfile"):
            for location in ("query", "header", "path"):
                for inherited in (False, True):
                    for required in (False, True):
                        document = copy.deepcopy(original)
                        for path in document["paths"].values():
                            operation = path.get("get", {})
                            if operation.get("operationId") == operation_id:
                                target = path if inherited else operation
                                target.setdefault("parameters", []).append(
                                    {
                                        "name": "new_parameter",
                                        "in": location,
                                        "required": required,
                                        "schema": {"type": "string"},
                                    }
                                )
                                break
                        check(
                            document,
                            f"{operation_id} {location} "
                            f"{'inherited' if inherited else 'operation'} "
                            f"{'required' if required else 'optional'}",
                            not required,
                            rejects_required=required,
                        )
        document = copy.deepcopy(original)
        document["paths"]["/v2/profile"] = document["paths"].pop("/v1/profile")
        history_route = next(
            path
            for path, value in document["paths"].items()
            if value.get("get", {}).get("operationId") == "searchHistory"
        )
        document["paths"]["/api/v2/history/{search_type}/{value}"] = document["paths"].pop(
            history_route
        )
        for path in document["paths"].values():
            operation = path.get("get", {})
            if operation.get("operationId") in ("searchHistory", "getDomainProfile"):
                operation.setdefault("parameters", []).extend(
                    [
                        {
                            "name": "optional_query",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "default": "do-not-send"},
                        },
                        {
                            "name": "X-Optional-Header",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string", "default": "do-not-send"},
                        },
                    ]
                )
        check(document, "profile and History route changes", True)
        result = run(
            [
                sys.executable,
                "-B",
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); import httpx; "
                "from shieldlabs import ShieldLabsManagement, ShieldLabs; "
                "requests=[]; transport=httpx.MockTransport(lambda r: "
                "(requests.append(r), httpx.Response(200,json={}))[1]); "
                "http=httpx.Client(transport=transport); "
                "client=ShieldLabsManagement(secret_key='fixture',"
                "domain='example.com',http_client=http); "
                "client.get_profile(); "
                "history=ShieldLabs(api_key='sec_aaaaaaaa-bbbbbbbb-cccccccc',http_client=http); "
                "history.history.search('user_hid','a@b+c%next',limit=1); "
                "assert [r.url.path for r in requests] == "
                "['/v2/profile','/api/v2/history/user_hid/a@b+c%next']; "
                "assert requests[1].url.raw_path.split(b'?')[0] == "
                "b'/api/v2/history/user_hid/a@b+c%25next'; "
                "assert not requests[0].url.params; "
                "assert dict(requests[1].url.params) == {'limit':'1','offset':'0'}; "
                "assert all('X-Optional-Header' not in r.headers for r in requests); http.close()",
                str(scratch / "src"),
            ]
        )
        if result.returncode:
            raise RuntimeError(f"Generated profile route not used at runtime: {result.stderr}")
        print("PASS real HTTP: changed routes used; escaping preserved; optional defaults not sent")


if __name__ == "__main__":
    main()
