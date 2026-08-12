from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text()
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"expected issue16 replacement missing in {path}")
    target.write_text(text.replace(old, new, 1))


def append_once(path: str, marker: str, content: str) -> None:
    target = Path(path)
    text = target.read_text()
    if marker not in text:
        target.write_text(text + content)


def allowlist_synthetic_basic_auth(path: str) -> None:
    target = Path(path)
    lines = target.read_text().splitlines()
    changed = False
    output: list[str] = []
    needle = "user" + ":" + "pass@"
    for line in lines:
        if needle in line and "pragma: allowlist secret" not in line:
            line += "  # pragma: allowlist secret"
            changed = True
        output.append(line)
    if changed:
        target.write_text("\n".join(output) + "\n")


def main() -> None:
    replace_once(
        "src/local_recall/metadata/activitywatch_client.py",
        "        if end <= start or not 1 <= limit <= MAX_EVENTS_PER_BUCKET:\n",
        "        if (\n"
        "            end <= start\n"
        "            or (end - start).total_seconds() > 10.0\n"
        "            or not 1 <= limit <= MAX_EVENTS_PER_BUCKET\n"
        "        ):\n",
    )
    replace_once(
        "src/local_recall/metadata/activitywatch.py",
        "            if event_type is ActivityWatchEventType.CURRENT_WINDOW:\n"
        "                capabilities.update({\"application\", \"window-title\"})\n"
        "            elif event_type is ActivityWatchEventType.AFK_STATUS:\n"
        "                capabilities.update({\"activity\", \"idle\"})\n"
        "            elif event_type is ActivityWatchEventType.WEB_TAB_CURRENT:\n"
        "                capabilities.add(\"domain\")\n",
        "            if event_type is ActivityWatchEventType.CURRENT_WINDOW:\n"
        "                capabilities.add(\"application\")\n"
        "                if self._settings.window_titles_enabled:\n"
        "                    capabilities.add(\"window-title\")\n"
        "            elif event_type is ActivityWatchEventType.AFK_STATUS:\n"
        "                capabilities.update({\"activity\", \"idle\"})\n"
        "            elif (\n"
        "                event_type is ActivityWatchEventType.WEB_TAB_CURRENT\n"
        "                and self._settings.activitywatch.url_mode\n"
        "                is ActivityWatchURLMode.DOMAIN_ONLY\n"
        "            ):\n"
        "                capabilities.add(\"domain\")\n",
    )
    replace_once(
        "src/local_recall/metadata/activitywatch.py",
        "        if _event_distance_seconds(event, observed_at) <= tolerance_seconds\n",
        "        if _event_distance_seconds(event, observed_at) <= tolerance_seconds\n"
        "        and abs((observed_at - event.timestamp).total_seconds())\n"
        "        <= tolerance_seconds\n",
    )

    append_once(
        "tests/unit/metadata/test_activitywatch.py",
        "test_old_long_running_event_is_not_treated_as_current",
        '''\n\n\ndef test_old_long_running_event_is_not_treated_as_current() -> None:\n    client = SyntheticClient(\n        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),\n        {\n            "window": (\n                event(\n                    ActivityWatchEventType.CURRENT_WINDOW,\n                    timestamp=NOW - timedelta(hours=1),\n                    duration_seconds=7200,\n                    application="old-long-event",\n                ),\n            )\n        },\n    )\n\n    with pytest.raises(ActivityWatchMetadataFailure) as captured:\n        asyncio.run(source(client).collect(request()))\n\n    assert captured.value.code is ActivityWatchMetadataFailureCode.NO_CORRELATED_EVENT\n\n\ndef test_far_future_event_is_rejected() -> None:\n    client = SyntheticClient(\n        (bucket("window", ActivityWatchEventType.CURRENT_WINDOW),),\n        {\n            "window": (\n                event(\n                    ActivityWatchEventType.CURRENT_WINDOW,\n                    timestamp=NOW + timedelta(seconds=30),\n                    duration_seconds=0,\n                    application="future",\n                ),\n            )\n        },\n    )\n\n    with pytest.raises(ActivityWatchMetadataFailure) as captured:\n        asyncio.run(source(client).collect(request()))\n\n    assert captured.value.code is ActivityWatchMetadataFailureCode.NO_CORRELATED_EVENT\n\n\ndef test_stale_afk_event_does_not_override_fresh_window_context() -> None:\n    client = SyntheticClient(\n        (\n            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),\n            bucket("afk", ActivityWatchEventType.AFK_STATUS),\n        ),\n        {\n            "window": (\n                event(ActivityWatchEventType.CURRENT_WINDOW, application="fresh-app"),\n            ),\n            "afk": (\n                event(\n                    ActivityWatchEventType.AFK_STATUS,\n                    timestamp=NOW - timedelta(seconds=30),\n                    duration_seconds=0,\n                    idle=True,\n                ),\n            ),\n        },\n    )\n\n    metadata = asyncio.run(source(client).collect(request()))\n\n    assert metadata.get("application") == "fresh-app"\n    assert metadata.get("idle") is None\n\n\ndef test_conflicting_afk_events_choose_latest_start_deterministically() -> None:\n    client = SyntheticClient(\n        (bucket("afk", ActivityWatchEventType.AFK_STATUS),),\n        {\n            "afk": (\n                event(\n                    ActivityWatchEventType.AFK_STATUS,\n                    timestamp=NOW - timedelta(milliseconds=500),\n                    duration_seconds=1,\n                    idle=False,\n                ),\n                event(\n                    ActivityWatchEventType.AFK_STATUS,\n                    timestamp=NOW - timedelta(seconds=1),\n                    duration_seconds=2,\n                    idle=True,\n                ),\n            )\n        },\n    )\n\n    metadata = asyncio.run(source(client).collect(request("idle")))\n\n    assert metadata.get("idle") is False\n\n\ndef test_probe_capabilities_respect_sensitive_field_configuration() -> None:\n    client = SyntheticClient(\n        (\n            bucket("window", ActivityWatchEventType.CURRENT_WINDOW),\n            bucket("afk", ActivityWatchEventType.AFK_STATUS),\n            bucket("web", ActivityWatchEventType.WEB_TAB_CURRENT),\n        ),\n        {},\n    )\n\n    defaults = asyncio.run(source(client).probe_capabilities())\n    enabled = asyncio.run(\n        source(\n            client,\n            titles=True,\n            url_mode=ActivityWatchURLMode.DOMAIN_ONLY,\n        ).probe_capabilities()\n    )\n\n    assert defaults == frozenset({"application", "activity", "idle"})\n    assert enabled == frozenset(\n        {"application", "window-title", "activity", "idle", "domain"}\n    )\n''',
    )
    append_once(
        "tests/unit/metadata/test_activitywatch_client.py",
        "test_client_rejects_event_query_wider_than_transport_policy",
        '''\n\n\ndef test_client_rejects_event_query_wider_than_transport_policy() -> None:\n    adapter, _ = client([encoded(bucket_payload("currentwindow"))])\n    asyncio.run(adapter.buckets(timeout_seconds=0.5))\n\n    with pytest.raises(ActivityWatchAdapterFailure) as captured:\n        asyncio.run(\n            adapter.events(\n                "bucket",\n                start=datetime(2026, 8, 12, 14, 0, tzinfo=UTC),\n                end=datetime(2026, 8, 12, 14, 0, 11, tzinfo=UTC),\n                limit=16,\n                timeout_seconds=0.5,\n            )\n        )\n\n    assert captured.value.code is ActivityWatchMetadataFailureCode.INVALID_REQUEST\n''',
    )
    append_once(
        "tests/security/test_activitywatch_architecture.py",
        "test_activitywatch_adapter_has_no_persistence_or_provider_imports",
        '''from __future__ import annotations\n\nimport ast\nfrom pathlib import Path\n\n_ACTIVITYWATCH_MODULES = (\n    Path("src/local_recall/metadata/activitywatch.py"),\n    Path("src/local_recall/metadata/activitywatch_client.py"),\n    Path("src/local_recall/metadata/activitywatch_http.py"),\n    Path("src/local_recall/metadata/activitywatch_types.py"),\n)\n\n\ndef test_activitywatch_adapter_has_no_persistence_or_provider_imports() -> None:\n    forbidden_prefixes = (\n        "local_recall.storage",\n        "local_recall.providers",\n        "local_recall.audit",\n        "local_recall.crypto",\n    )\n    imports: set[str] = set()\n\n    for path in _ACTIVITYWATCH_MODULES:\n        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))\n        for node in ast.walk(tree):\n            if isinstance(node, ast.Import):\n                imports.update(alias.name for alias in node.names)\n            elif isinstance(node, ast.ImportFrom) and node.module is not None:\n                imports.add(node.module)\n\n    assert not any(\n        name.startswith(prefix)\n        for name in imports\n        for prefix in forbidden_prefixes\n    )\n''',
    )
    append_once(
        "docs/configuration.md",
        "## ActivityWatch metadata",
        '''\n\n## ActivityWatch metadata\n\nOptional ActivityWatch enrichment is configured under `[metadata.activitywatch]`. The endpoint is restricted to a loopback HTTP origin, URL capture defaults to `disabled`, and the only enabled URL mode is `domain-only`. Window-title capture remains controlled independently by `metadata.window_titles_enabled`. See [ActivityWatch metadata](activitywatch.md) for bucket discovery, correlation, transport bounds, privacy, fallback, and sanitized troubleshooting.\n''',
    )

    for test_path in (
        "tests/security/test_activitywatch_transport.py",
        "tests/unit/metadata/test_activitywatch.py",
        "tests/unit/metadata/test_activitywatch_client.py",
    ):
        allowlist_synthetic_basic_auth(test_path)

    for temporary in (
        ".github/workflows/issue16-hardening.yml",
        ".github/workflows/issue16-finalize.yml",
        "scripts/issue16-finalize.py",
    ):
        Path(temporary).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
