from local_recall.indicator import IndicatorState


def test_indicator_state_is_closed_and_content_free() -> None:
    assert tuple(state.value for state in IndicatorState) == (
        "off",
        "paused",
        "recording",
        "privacy",
        "locked",
        "overloaded",
        "faulted",
        "unavailable",
    )
