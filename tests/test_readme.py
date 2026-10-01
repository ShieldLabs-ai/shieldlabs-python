"""README code samples: every Python block compiles, and the Quick start runs as pasted."""

from __future__ import annotations

import ast
import importlib.util
import re
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest
import respx

from _support import API_KEY, HISTORY_HOST, load_bytes, load_json, sign

README = Path(__file__).resolve().parent.parent / "README.md"
SECRET = "whsec_your_signing_secret"
_PYTHON_BLOCK = re.compile(r"```python\n(.*?)```", re.DOTALL)


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _python_blocks() -> list[str]:
    return _PYTHON_BLOCK.findall(_readme())


def _quick_start() -> str:
    section = _readme().split("\n## Quick start\n", 1)[1].split("\n## ", 1)[0]
    blocks = _PYTHON_BLOCK.findall(section)
    assert len(blocks) == 1
    return blocks[0]


def _import_file(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("index", range(len(_python_blocks())))
def test_readme_python_blocks_compile(index: int) -> None:
    # Top-level await is allowed because the async section shows statements, not a module.
    compile(
        _python_blocks()[index],
        f"README.md python block {index}",
        "exec",
        flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
    )


def test_quick_start_runs_as_pasted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SHIELDLABS_API_KEY", API_KEY)
    monkeypatch.setenv("SHIELDLABS_WEBHOOK_SECRET", SECRET)
    script = tmp_path / "readme_quick_start.py"
    script.write_text(_quick_start(), encoding="utf-8")
    row = dict(load_json("history-page.json")["data"][1])  # trusted, with device signals
    row["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000")

    with respx.mock(assert_all_called=False) as router:
        route = router.get(host=HISTORY_HOST).respond(200, json={"data": [row], "total": 1})
        quick_start = _import_file(script)
        assert quick_start.allow_signup(row["request_id"]) is True
        # One identification authorizes one action: the same request ID is refused next time.
        assert quick_start.allow_signup(row["request_id"]) is False
        quick_start.client.close()
    assert route.call_count == 2

    body = load_bytes("webhook-ping.raw.txt")
    quick_start.on_webhook(body, sign(SECRET, body))
    assert capsys.readouterr().out == "webhook.ping\n"
