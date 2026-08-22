from __future__ import annotations

import importlib


def test_xorg_capture_backend_module_exists() -> None:
    module = importlib.import_module("local_recall.capture.xorg")

    assert module.XorgCaptureBackend
