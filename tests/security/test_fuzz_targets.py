from __future__ import annotations

import json
import string
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from local_recall.backup.archive import BackupArchive, RestoreFailure
from local_recall.cli_contract import CliDiagnosticPayload
from local_recall.config.errors import ConfigurationError
from local_recall.config.loader import load_configuration_mapping
from local_recall.ipc_transport import _decode_diagnostic_payload
from local_recall.metadata.script_adapter import ScriptAdapterFailure, _parse
from local_recall.redaction.detector import DeterministicSecretDetector

# Deterministic property-based fuzzing for the required parser surfaces.
#
# Seeds are pinned via derandomize=True, so CI executions are reproducible by
# default. To reproduce or extend a corpus run:
#
#   uv run --no-sync pytest tests/security/test_fuzz_targets.py \
#       --hypothesis-seed=<N> -k <target>
#
# Any failing example is printed by pytest with its seed and can be replayed
# with the same command.

MAX_EXAMPLES = 64

_ARCHIVE_REASONS = frozenset(
    {
        "archive is truncated",
        "archive header is invalid",
        "archive manifest is invalid",
        "archive schema version is incompatible",
        "archive body is truncated",
        "archive body digest mismatch",
        "archive record is corrupt",
        "archive record count mismatch",
    }
)

_text = st.text(alphabet=st.sampled_from(string.printable), max_size=256)
_json_scalars = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**31), max_value=2**31)
    | st.text(max_size=64),
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(st.text(max_size=16), children, max_size=8),
    max_leaves=12,
)


@settings(derandomize=True, max_examples=MAX_EXAMPLES, deadline=None)
@given(st.dictionaries(st.text(max_size=24), _json_scalars, max_size=24))
def test_config_parser_never_leaks_input_values_in_errors(mapping: dict[str, object]) -> None:
    try:
        load_configuration_mapping(mapping)
    except ConfigurationError as error:
        rendered = str(error)
        assert len(rendered) <= 512
        for value in mapping.values():
            if isinstance(value, str) and len(value) >= 12:
                assert value not in rendered


@settings(derandomize=True, max_examples=MAX_EXAMPLES, deadline=None)
@given(_text)
def test_redaction_detector_scan_never_raises_or_overruns(text: str) -> None:
    detector = DeterministicSecretDetector()
    result = detector.scan(text)
    for match in result.matches:
        assert match.start >= 0
        assert match.end <= len(text)
        assert match.start <= match.end


@settings(derandomize=True, max_examples=MAX_EXAMPLES, deadline=None)
@given(st.binary(max_size=512))
def test_archive_reader_rejects_garbage_with_fixed_reasons(data: bytes) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "archive.bin"
        path.write_bytes(data)
        try:
            BackupArchive.read(path, max_blob_bytes=4096)
        except RestoreFailure as error:
            assert str(error) in _ARCHIVE_REASONS
        except OSError:
            raise AssertionError("archive reader raised an unexpected OSError")


@settings(derandomize=True, max_examples=MAX_EXAMPLES, deadline=None)
@given(_json_scalars)
def test_ipc_diagnostic_decoder_is_fail_closed(value: object) -> None:
    try:
        decoded = _decode_diagnostic_payload(value)
    except ValueError:
        return
    if decoded is not None:
        assert isinstance(decoded, CliDiagnosticPayload)


@settings(derandomize=True, max_examples=MAX_EXAMPLES, deadline=None)
@given(st.binary(max_size=256), st.integers(min_value=0, max_value=9))
def test_script_adapter_output_parser_is_fail_closed(stdout: bytes, schema: int) -> None:
    try:
        payload = _parse(stdout, schema)
    except ScriptAdapterFailure as error:
        assert str(error) == "script output is invalid"
        return
    assert set(payload) == {"application", "workspace"}
    for value in payload.values():
        assert value is None or (isinstance(value, str) and 0 < len(value) <= 4096)
