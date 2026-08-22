from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from local_recall.domain.lifecycle import CaptureGeneration

_HASH_BITS = 64
_HASH_COLUMNS = 9
_HASH_ROWS = 8
_NS_PER_SECOND = 1_000_000_000
_MAX_REVISION_LENGTH = 256
_MAX_CONTEXT_VALUE_LENGTH = 4096


class CaptureTriggerKind(StrEnum):
    NONE = "none"
    CADENCE = "cadence"
    CONTEXT_CHANGE = "context-change"


class FrameDisposition(StrEnum):
    ACCEPT = "accept"
    COALESCE = "coalesce"


@dataclass(frozen=True, slots=True, repr=False)
class DedupContext:
    generation: CaptureGeneration
    policy_revision: str
    configuration_revision: str
    application: str | None = None
    workspace: str | None = None
    window_id: str | None = None

    def __post_init__(self) -> None:
        _require_bounded_text(self.policy_revision, "policy_revision", _MAX_REVISION_LENGTH)
        _require_bounded_text(
            self.configuration_revision,
            "configuration_revision",
            _MAX_REVISION_LENGTH,
        )
        for name, value in (
            ("application", self.application),
            ("workspace", self.workspace),
            ("window_id", self.window_id),
        ):
            if value is not None:
                _require_bounded_text(value, name, _MAX_CONTEXT_VALUE_LENGTH)

    @property
    def privacy_scope(self) -> tuple[CaptureGeneration, str, str]:
        return (self.generation, self.policy_revision, self.configuration_revision)

    @property
    def metadata_key(self) -> tuple[str | None, str | None, str | None]:
        return (self.application, self.workspace, self.window_id)

    def __repr__(self) -> str:
        return f"DedupContext(generation={self.generation.value}, content=redacted)"


@dataclass(frozen=True, slots=True)
class CaptureTriggerDecision:
    kind: CaptureTriggerKind
    effective_cadence_seconds: float


@dataclass(frozen=True, slots=True)
class FrameDecision:
    disposition: FrameDisposition
    span_count: int
    span_started_monotonic_ns: int
    span_last_seen_monotonic_ns: int


class AdaptiveCaptureController:
    __slots__ = (
        "_backoff_multiplier",
        "_cadence_seconds",
        "_change_threshold",
        "_debounce_ns",
        "_last_capture_context",
        "_last_capture_ns",
        "_last_dedup_context",
        "_last_fingerprint",
        "_max_backoff_multiplier",
        "_pending_change_context",
        "_pending_change_since_ns",
        "_span_count",
        "_span_last_seen_ns",
        "_span_started_ns",
    )

    def __init__(
        self,
        *,
        cadence_seconds: float,
        change_threshold: float,
        debounce_seconds: float,
        max_backoff_multiplier: int = 8,
    ) -> None:
        if not 0.0 < cadence_seconds <= 3600.0:
            raise ValueError("cadence_seconds must be in (0, 3600]")
        if not 0.0 <= change_threshold <= 1.0:
            raise ValueError("change_threshold must be in [0, 1]")
        if not 0.0 <= debounce_seconds <= 60.0:
            raise ValueError("debounce_seconds must be in [0, 60]")
        if max_backoff_multiplier < 1 or max_backoff_multiplier > 64:
            raise ValueError("max_backoff_multiplier must be in [1, 64]")
        if max_backoff_multiplier & (max_backoff_multiplier - 1):
            raise ValueError("max_backoff_multiplier must be a power of two")

        self._cadence_seconds = cadence_seconds
        self._change_threshold = change_threshold
        self._debounce_ns = int(debounce_seconds * _NS_PER_SECOND)
        self._max_backoff_multiplier = max_backoff_multiplier
        self._backoff_multiplier = 1
        self._last_capture_ns: int | None = None
        self._last_capture_context: DedupContext | None = None
        self._pending_change_context: DedupContext | None = None
        self._pending_change_since_ns: int | None = None
        self._last_dedup_context: DedupContext | None = None
        self._last_fingerprint: int | None = None
        self._span_count = 0
        self._span_started_ns: int | None = None
        self._span_last_seen_ns: int | None = None

    @property
    def pending_change_count(self) -> int:
        return int(self._pending_change_context is not None)

    @property
    def effective_cadence_seconds(self) -> float:
        return self._cadence_seconds * self._backoff_multiplier

    def __repr__(self) -> str:
        return (
            "AdaptiveCaptureController("
            f"effective_cadence_seconds={self.effective_cadence_seconds}, "
            f"pending_change_count={self.pending_change_count}, "
            f"span_count={self._span_count})"
        )

    def poll(
        self,
        *,
        context: DedupContext,
        now_monotonic_ns: int,
    ) -> CaptureTriggerDecision:
        _require_monotonic_ns(now_monotonic_ns)
        effective = self.effective_cadence_seconds
        if self._last_capture_ns is None or self._last_capture_context is None:
            return CaptureTriggerDecision(CaptureTriggerKind.CADENCE, effective)
        if now_monotonic_ns < self._last_capture_ns:
            raise ValueError("monotonic time moved backwards")

        previous = self._last_capture_context
        if context.privacy_scope != previous.privacy_scope:
            self._clear_pending_change()
            return CaptureTriggerDecision(CaptureTriggerKind.CADENCE, effective)

        if context.metadata_key != previous.metadata_key:
            if self._pending_change_context is None or (
                context.metadata_key != self._pending_change_context.metadata_key
            ):
                self._pending_change_context = context
                self._pending_change_since_ns = now_monotonic_ns
            else:
                assert self._pending_change_since_ns is not None
                if now_monotonic_ns < self._pending_change_since_ns:
                    raise ValueError("monotonic time moved backwards")
                if now_monotonic_ns - self._pending_change_since_ns >= self._debounce_ns:
                    self._clear_pending_change()
                    return CaptureTriggerDecision(CaptureTriggerKind.CONTEXT_CHANGE, effective)
        else:
            self._clear_pending_change()

        cadence_ns = int(effective * _NS_PER_SECOND)
        if now_monotonic_ns - self._last_capture_ns >= cadence_ns:
            return CaptureTriggerDecision(CaptureTriggerKind.CADENCE, effective)
        return CaptureTriggerDecision(CaptureTriggerKind.NONE, effective)

    def mark_capture_started(
        self,
        *,
        context: DedupContext,
        now_monotonic_ns: int,
    ) -> None:
        _require_monotonic_ns(now_monotonic_ns)
        if self._last_capture_ns is not None and now_monotonic_ns < self._last_capture_ns:
            raise ValueError("monotonic time moved backwards")
        if (
            self._last_capture_context is not None
            and context.privacy_scope != self._last_capture_context.privacy_scope
        ):
            self._reset_dedup_state()
        self._last_capture_context = context
        self._last_capture_ns = now_monotonic_ns
        self._clear_pending_change()

    def classify_frame(
        self,
        *,
        context: DedupContext,
        fingerprint: int,
        observed_at_monotonic_ns: int,
    ) -> FrameDecision:
        _require_monotonic_ns(observed_at_monotonic_ns)
        if fingerprint < 0 or fingerprint >= 1 << _HASH_BITS:
            raise ValueError("fingerprint must be an unsigned 64-bit integer")
        if (
            self._span_last_seen_ns is not None
            and observed_at_monotonic_ns < self._span_last_seen_ns
        ):
            raise ValueError("monotonic time moved backwards")

        if self._last_dedup_context != context or self._last_fingerprint is None:
            return self._accept_new_span(context, fingerprint, observed_at_monotonic_ns)

        changed_bits = (self._last_fingerprint ^ fingerprint).bit_count()
        similarity_delta = changed_bits / _HASH_BITS
        if similarity_delta <= self._change_threshold:
            assert self._span_started_ns is not None
            self._span_count += 1
            self._span_last_seen_ns = observed_at_monotonic_ns
            return FrameDecision(
                FrameDisposition.COALESCE,
                self._span_count,
                self._span_started_ns,
                observed_at_monotonic_ns,
            )
        return self._accept_new_span(context, fingerprint, observed_at_monotonic_ns)

    def note_overload(self) -> None:
        self._backoff_multiplier = min(
            self._max_backoff_multiplier,
            self._backoff_multiplier * 2,
        )

    def note_success(self) -> None:
        self._backoff_multiplier = max(1, self._backoff_multiplier // 2)

    def reset(self) -> None:
        self._last_capture_ns = None
        self._last_capture_context = None
        self._clear_pending_change()
        self._reset_dedup_state()
        self._backoff_multiplier = 1

    def _accept_new_span(
        self,
        context: DedupContext,
        fingerprint: int,
        observed_at_monotonic_ns: int,
    ) -> FrameDecision:
        self._last_dedup_context = context
        self._last_fingerprint = fingerprint
        self._span_count = 1
        self._span_started_ns = observed_at_monotonic_ns
        self._span_last_seen_ns = observed_at_monotonic_ns
        return FrameDecision(
            FrameDisposition.ACCEPT,
            1,
            observed_at_monotonic_ns,
            observed_at_monotonic_ns,
        )

    def _clear_pending_change(self) -> None:
        self._pending_change_context = None
        self._pending_change_since_ns = None

    def _reset_dedup_state(self) -> None:
        self._last_dedup_context = None
        self._last_fingerprint = None
        self._span_count = 0
        self._span_started_ns = None
        self._span_last_seen_ns = None


def perceptual_dhash_rgb8(
    pixels: bytes | bytearray,
    *,
    width: int,
    height: int,
) -> int:
    if width <= 0 or height <= 0:
        raise ValueError("image dimensions must be positive")
    expected_size = width * height * 3
    if len(pixels) != expected_size:
        raise ValueError("RGB8 buffer size does not match dimensions")

    fingerprint = 0
    bit = 0
    for sample_y in range(_HASH_ROWS):
        y = _sample_coordinate(sample_y, _HASH_ROWS, height)
        row: list[int] = []
        for sample_x in range(_HASH_COLUMNS):
            x = _sample_coordinate(sample_x, _HASH_COLUMNS, width)
            offset = (y * width + x) * 3
            red = pixels[offset]
            green = pixels[offset + 1]
            blue = pixels[offset + 2]
            row.append((299 * red + 587 * green + 114 * blue) // 1000)
        for column in range(_HASH_COLUMNS - 1):
            if row[column] > row[column + 1]:
                fingerprint |= 1 << bit
            bit += 1
    return fingerprint


def _sample_coordinate(index: int, samples: int, extent: int) -> int:
    if extent == 1:
        return 0
    return index * (extent - 1) // (samples - 1)


def _require_monotonic_ns(value: int) -> None:
    if value < 0:
        raise ValueError("monotonic timestamp must be non-negative")


def _require_bounded_text(value: str, name: str, limit: int) -> None:
    if not value or len(value) > limit:
        raise ValueError(f"{name} must contain 1..{limit} characters")
