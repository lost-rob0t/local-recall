from __future__ import annotations

import asyncio
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from local_recall.domain.capture import MetadataRequest
from local_recall.domain.lifecycle import CaptureGeneration
from local_recall.metadata.script_adapter import (
    ScriptAdapterConfig,
    ScriptAdapterFailure,
    ScriptMetadataAdapter,
)

_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def _request() -> MetadataRequest:
    return MetadataRequest(
        job_id=uuid4(),
        generation=CaptureGeneration(1),
        deadline_monotonic_ns=1 << 62,
    )


def _config(path: Path, **overrides: object) -> ScriptAdapterConfig:
    values: dict[str, object] = {
        "name": "custom-script",
        "path": path,
        "timeout_seconds": 5.0,
        "max_output_bytes": 65_536,
    }
    values.update(overrides)
    return ScriptAdapterConfig(**values)  # type: ignore[arg-type]


def _write_script(tmp_path: Path, body: str, *, mode: int = 0o700, name: str = "probe.py") -> Path:
    script = tmp_path / name
    script.write_text(body)
    script.chmod(mode)
    return script


def _py(body: str) -> str:
    return "#!/usr/bin/env python3\n" + body


def test_valid_script_collects_redacted_fields_with_provenance(tmp_path: Path) -> None:
    payload = {"application": "emacs", "schema_version": 1, "workspace": "dev"}
    script = _write_script(tmp_path, _py(f"import json;print(json.dumps({payload!r}))"))
    adapter = ScriptMetadataAdapter(_config(script), now=_NOW)

    async def exercise() -> None:
        metadata = await adapter.collect(_request())
        names = {field.name: field.value for field in metadata.fields}
        assert names["application"] == "emacs"
        assert names["workspace"] == "dev"
        provenance = metadata.fields[0].provenance[0]
        assert provenance.source_id == "custom-script"
        assert provenance.adapter_revision is not None and len(provenance.adapter_revision) == 12
        assert provenance.observed_at == _NOW

    asyncio.run(exercise())


def test_unwritable_permissions_and_symlinks_are_rejected(tmp_path: Path) -> None:
    group_writable = _write_script(tmp_path, _py("print(1)"), mode=0o770, name="a.py")
    with pytest.raises(ScriptAdapterFailure, match="permission"):
        ScriptMetadataAdapter(_config(group_writable))

    real = _write_script(tmp_path, _py("print(1)"), name="real.py")
    link = tmp_path / "link.py"
    link.symlink_to(real)
    with pytest.raises(ScriptAdapterFailure, match="symlink"):
        ScriptMetadataAdapter(_config(link))

    with pytest.raises(ValueError, match="absolute"):
        ScriptAdapterConfig(name="rel", path=Path("relative.py"))


def test_changed_script_is_disabled_until_reapproved(tmp_path: Path) -> None:
    import hashlib

    script = _write_script(tmp_path, _py("print(1)"))
    pin = hashlib.sha256(script.read_bytes()).hexdigest()

    adapter = ScriptMetadataAdapter(_config(script, pin_sha256=pin))
    assert adapter.script_digest == pin

    script.write_text(_py("print(2)"))
    with pytest.raises(ScriptAdapterFailure, match="pin"):
        asyncio.run(adapter.collect(_request()))


def test_malformed_or_versioned_output_is_rejected(tmp_path: Path) -> None:
    for body in (
        _py("print('not-json')"),
        _py('print(\'{"application":"x"}\')'),
        _py('print(\'{"application":"x","schema_version":99,"workspace":null}\')'),
        _py('print(\'{"application":"x","schema_version":1,"workspace":null,"extra":1}\')'),
        _py('print(\'{"application":123,"schema_version":1,"workspace":null}\')'),
    ):
        script = _write_script(tmp_path, body, name=f"bad{abs(hash(body))}.py")
        adapter = ScriptMetadataAdapter(_config(script))
        with pytest.raises(ScriptAdapterFailure, match="output"):
            asyncio.run(adapter.collect(_request()))


def test_timeout_and_oversized_output_fail_and_kill(tmp_path: Path) -> None:
    slow = _write_script(
        tmp_path,
        _py("import time;print('hi',flush=True);time.sleep(30)"),
        name="slow.py",
    )
    adapter = ScriptMetadataAdapter(_config(slow, timeout_seconds=0.3))
    with pytest.raises(ScriptAdapterFailure, match="timeout"):
        asyncio.run(adapter.collect(_request()))

    big = _write_script(
        tmp_path,
        _py("print('x' * 200000)"),
        name="big.py",
    )
    adapter = ScriptMetadataAdapter(_config(big, max_output_bytes=1024))
    with pytest.raises(ScriptAdapterFailure, match="output"):
        asyncio.run(adapter.collect(_request()))


def test_window_values_cannot_alter_arguments_and_env_is_allowlisted(tmp_path: Path) -> None:
    probe = _write_script(
        tmp_path,
        _py(
            "import json,os\n"
            "print(json.dumps({'application': os.environ.get('SCRIPT_VALUE', '') + '|' + os.environ.get('HOSTILE', ''), 'schema_version': 1, 'workspace': None}))"
        ),
        name="envprobe.py",
    )
    recorded: list[list[str]] = []
    real_exec = asyncio.create_subprocess_exec

    async def spy(*args: object, **kwargs: object):
        recorded.append([str(item) for item in args])
        return await real_exec(*args, **kwargs)  # type: ignore[arg-type]

    import local_recall.metadata.script_adapter as module

    module.create_subprocess_exec = spy  # type: ignore[assignment]
    os.environ["HOSTILE"] = "injected"
    adapter = ScriptMetadataAdapter(
        _config(probe, args=("fixed-arg",), env_allowlist=("SCRIPT_VALUE",)),
        environ={"PATH": os.environ["PATH"], "SCRIPT_VALUE": "allowed", "HOSTILE": "injected"},
    )

    async def exercise() -> None:
        metadata = await adapter.collect(_request())
        text = str(metadata.fields[0].value)
        assert "allowed" in text
        assert "injected" not in text

    try:
        asyncio.run(exercise())
    finally:
        module.create_subprocess_exec = real_exec  # type: ignore[assignment]
        os.environ.pop("HOSTILE", None)
    assert recorded[0][:2] == [str(probe), "fixed-arg"]


def test_working_directory_is_sanitized(tmp_path: Path) -> None:
    probe = _write_script(
        tmp_path,
        _py(
            "import json,os\nprint(json.dumps({'application': os.getcwd(), 'schema_version': 1, 'workspace': None}))"
        ),
        name="cwd.py",
    )
    adapter = ScriptMetadataAdapter(_config(probe))

    async def exercise() -> None:
        metadata = await adapter.collect(_request())
        cwd = str(metadata.fields[0].value)
        assert cwd.startswith(tempfile.gettempdir())
        assert cwd != str(Path.cwd())

    asyncio.run(exercise())
