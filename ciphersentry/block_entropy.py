"""Block-level entropy evidence (M3B Step 1). Evidence only: never scored.

The folder monitor already reads at most the first 64 KiB of a file and computes
one Shannon entropy value for that whole sample. This module splits the same
bytes into 4 KiB blocks and measures each block, so a change confined to part
of a file can be seen even when the whole-sample value hardly moves.

Nothing here contributes to a risk score, an alert or a response decision. The
whole-sample ``entropy_before`` / ``entropy_after`` values and their scoring are
unchanged; this evidence is recorded beside them. See
docs/BLOCK_ENTROPY_EVIDENCE.md.

Representation:
- Block entropy is stored in milli-bits per byte (an integer 0..8000), so values
  are deterministic and compact. Exported values have at most three decimals.
- A CRC-32 per block is kept in memory only, to tell changed from unchanged
  blocks. It is never exported. Equal CRC-32 means "unchanged" with a 2**-32
  chance of an undetected change; a different CRC-32 always means changed.
- Missing evidence is explicit: a side is ``null`` with a reason, never zero.
"""
from __future__ import annotations

import math
import struct
import zlib
from collections import Counter
from itertools import chain

FORMAT = "block-entropy-v1"
BLOCK_SIZE = 4 * 1024
MAX_SAMPLE_BYTES = 64 * 1024
MAX_BLOCKS = MAX_SAMPLE_BYTES // BLOCK_SIZE
_MILLI = 1000

# Why a side has no measurement.
BEFORE_MISSING = frozenset({
    "not_in_baseline",      # new file, baseline limit reached, or unreadable when the baseline was taken
    "not_measured",         # block collection was switched off when the baseline was taken
    "deferred_under_load",  # the baseline sample was taken while the monitor was backlogged
})
AFTER_MISSING = frozenset({
    "deleted",              # the file no longer exists after a delete notification
    "unreadable",           # vanished, not a regular file, or the read failed
    "not_measured",
    "deferred_under_load",  # sampled while the monitor was backlogged; whole-sample entropy only
})
# A missing side is unknown evidence, never evidence of suspicious (or benign) activity.
# Per-block comparison result, by block index.
STATUSES = ("changed", "unchanged", "length_changed", "before_only", "after_only")
_CODE = {name: index for index, name in enumerate(STATUSES)}


def _entropy(counts, size: int) -> float:
    # The same expression as engine.shannon_entropy, applied to given counts.
    if not size:
        return 0.0
    return -sum((count / size) * math.log2(count / size) for count in counts)


# (c/4096) * log2(c/4096) for every possible byte count in a full block: the
# same terms as the expression above, precomputed to avoid repeated log2 calls.
_FULL_BLOCK_TERMS = (0.0,) + tuple((count / BLOCK_SIZE) * math.log2(count / BLOCK_SIZE)
                                   for count in range(1, BLOCK_SIZE + 1))


def _block_entropy(counts: Counter, size: int) -> float:
    if size == BLOCK_SIZE:
        return -sum(map(_FULL_BLOCK_TERMS.__getitem__, counts.values()))
    return _entropy(counts.values(), size)


def _block_lengths(sample_bytes: int) -> list[int]:
    full, rest = divmod(sample_bytes, BLOCK_SIZE)
    return [BLOCK_SIZE] * full + ([rest] if rest else [])


class BlockSample:
    """Per-block measurement of one file sample. Immutable and compact."""

    __slots__ = ("file_size", "sample_bytes", "short_read", "_entropy", "_digests")

    def __init__(self, file_size: int, sample_bytes: int, short_read: bool, entropy: bytes, digests: bytes | None):
        object.__setattr__(self, "file_size", file_size)
        object.__setattr__(self, "sample_bytes", sample_bytes)
        object.__setattr__(self, "short_read", short_read)
        object.__setattr__(self, "_entropy", entropy)    # little-endian uint16 milli-bits per block
        object.__setattr__(self, "_digests", digests)    # little-endian uint32 CRC-32 per block, or None

    def __setattr__(self, name, value):
        raise AttributeError("BlockSample is immutable")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self  # immutable

    def __eq__(self, other):
        if not isinstance(other, BlockSample):
            return NotImplemented
        return (self.file_size, self.sample_bytes, self.short_read, self._entropy, self._digests) == (
            other.file_size, other.sample_bytes, other.short_read, other._entropy, other._digests)

    __hash__ = None

    @property
    def block_count(self) -> int:
        return len(self._entropy) // 2

    def entropy_millibits(self) -> tuple[int, ...]:
        return struct.unpack(f"<{self.block_count}H", self._entropy)

    def entropies(self) -> list[float]:
        return [value / _MILLI for value in self.entropy_millibits()]

    def digests(self) -> tuple[int, ...] | None:
        return None if self._digests is None else struct.unpack(f"<{self.block_count}I", self._digests)

    def lengths(self) -> list[int]:
        return _block_lengths(self.sample_bytes)

    def to_dict(self) -> dict:
        return {"file_size": self.file_size, "sample_bytes": self.sample_bytes,
                "short_read": self.short_read, "entropy": self.entropies()}


def measure_sample(data: bytes, file_size: int) -> tuple[float, BlockSample]:
    """Whole-sample entropy and 4 KiB block measurements in one pass (no extra I/O).

    Bytes are counted once per block; the block counts are then merged for the
    whole-sample value. The merged counts are summed in the same
    first-occurrence order as ``Counter(data)`` with the same expression, so the
    whole-sample value is bit-identical to ``engine.shannon_entropy(data)``
    (tests check this exactly).

    The final block may be shorter than 4 KiB. ``short_read`` is True when fewer
    bytes were read than the file size reported just before the read (for
    example, the file was truncated while being sampled).
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_SAMPLE_BYTES:
        raise ValueError("data must be bytes of at most 64 KiB")
    if type(file_size) is not int or file_size < 0:
        raise ValueError("file_size must be a nonnegative integer")
    data = bytes(data)
    totals = [0] * 256
    block_counts, entropy, digests = [], [], []
    for start in range(0, len(data), BLOCK_SIZE):
        block = data[start:start + BLOCK_SIZE]
        counts = Counter(block)
        block_counts.append(counts)
        entropy.append(round(_block_entropy(counts, len(block)) * _MILLI))
        digests.append(zlib.crc32(block))
        for value, count in counts.items():
            totals[value] += count
    # Byte values in order of first occurrence in the sample, as Counter(data) has them.
    order = dict.fromkeys(chain.from_iterable(block_counts))
    sample = BlockSample(file_size, len(data), len(data) < min(file_size, MAX_SAMPLE_BYTES),
                         struct.pack(f"<{len(entropy)}H", *entropy), struct.pack(f"<{len(digests)}I", *digests))
    return _entropy((totals[value] for value in order), len(data)), sample


def measure_blocks(data: bytes, file_size: int) -> BlockSample:
    """Block measurements only; see ``measure_sample``."""
    return measure_sample(data, file_size)[1]


def _statuses(before: BlockSample, after: BlockSample) -> bytes:
    before_lengths, after_lengths = before.lengths(), after.lengths()
    before_digests, after_digests = before.digests(), after.digests()
    codes = []
    for index in range(max(len(before_lengths), len(after_lengths))):
        if index >= len(after_lengths):
            status = "before_only"
        elif index >= len(before_lengths):
            status = "after_only"
        elif before_lengths[index] != after_lengths[index]:
            status = "length_changed"
        else:
            status = "unchanged" if before_digests[index] == after_digests[index] else "changed"
        codes.append(_CODE[status])
    return bytes(codes)


class BlockEvidence:
    """Before/after block measurements for one observed event.

    Holds references to the monitor's samples (no copies) plus one status byte
    per block, so per-event memory stays small.
    """

    __slots__ = ("before", "before_missing", "after", "after_missing", "_statuses")

    def __init__(self, before: BlockSample | None, after: BlockSample | None, *,
                 before_missing: str | None = None, after_missing: str | None = None, statuses: bytes | None = None):
        if (before is None) != (before_missing is not None) or (after is None) != (after_missing is not None):
            raise ValueError("Each side needs either a measurement or a missing reason")
        if before_missing is not None and before_missing not in BEFORE_MISSING:
            raise ValueError("Unknown before_missing reason")
        if after_missing is not None and after_missing not in AFTER_MISSING:
            raise ValueError("Unknown after_missing reason")
        if before is not None and after is not None and statuses is None:
            if before.digests() is None or after.digests() is None:
                raise ValueError("Block statuses need digests or an explicit status list")
            statuses = _statuses(before, after)
        elif before is None or after is None:
            statuses = None
        for name, value in (("before", before), ("before_missing", before_missing), ("after", after),
                            ("after_missing", after_missing), ("_statuses", statuses)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("BlockEvidence is immutable")

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self  # immutable

    def __eq__(self, other):
        if not isinstance(other, BlockEvidence):
            return NotImplemented
        return self.to_dict() == other.to_dict()

    __hash__ = None

    def statuses(self) -> list[str] | None:
        return None if self._statuses is None else [STATUSES[code] for code in self._statuses]

    def summary(self) -> dict | None:
        statuses = self.statuses()
        if statuses is None:
            return None
        counts = {name: statuses.count(name) for name in STATUSES}
        before, after = self.before.entropy_millibits(), self.after.entropy_millibits()
        rises = [after[i] - before[i] for i, status in enumerate(statuses) if status == "changed"]
        counts["max_rise"] = max(rises) / _MILLI if rises else None
        return counts

    def to_dict(self) -> dict:
        return {
            "format": FORMAT, "block_size": BLOCK_SIZE,
            "before": self.before.to_dict() if self.before is not None else None,
            "before_missing": self.before_missing,
            "after": self.after.to_dict() if self.after is not None else None,
            "after_missing": self.after_missing,
            "blocks": self.statuses(),
            "summary": self.summary(),
        }

    @classmethod
    def from_dict(cls, value) -> "BlockEvidence":
        """Load untrusted evidence (exports, IPC). Strict: refuses anything inconsistent."""
        if not isinstance(value, dict) or set(value) != {"format", "block_size", "before", "before_missing",
                                                         "after", "after_missing", "blocks", "summary"}:
            raise ValueError("block_entropy must be an object with exactly the block-entropy-v1 fields")
        if value["format"] != FORMAT or type(value["block_size"]) is not int or value["block_size"] != BLOCK_SIZE:
            raise ValueError("Unsupported block_entropy format or block size")
        before = _side_from_dict(value["before"], "before")
        after = _side_from_dict(value["after"], "after")
        for name in ("before_missing", "after_missing"):
            if value[name] is not None and type(value[name]) is not str:
                raise ValueError(f"{name} must be a string or null")
        blocks = value["blocks"]
        statuses = None
        if before is not None and after is not None:
            if not isinstance(blocks, list) or any(type(s) is not str or s not in _CODE for s in blocks):
                raise ValueError("blocks must list known block statuses")
            statuses = bytes(_CODE[s] for s in blocks)
            _check_statuses(before, after, blocks)
        elif blocks is not None:
            raise ValueError("blocks must be null when a side is missing")
        evidence = cls(before, after, before_missing=value["before_missing"],
                       after_missing=value["after_missing"], statuses=statuses)
        if value["summary"] != evidence.summary():
            raise ValueError("block_entropy summary does not match its blocks")
        return evidence


def _side_from_dict(value, name: str) -> BlockSample | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"file_size", "sample_bytes", "short_read", "entropy"}:
        raise ValueError(f"block_entropy {name} must be null or an object with the measurement fields")
    file_size, sample_bytes, short_read, entropy = (value[k] for k in ("file_size", "sample_bytes", "short_read", "entropy"))
    if type(file_size) is not int or file_size < 0:
        raise ValueError(f"block_entropy {name}.file_size must be a nonnegative integer")
    # sample_bytes may exceed file_size: a file can grow between fstat and read.
    if type(sample_bytes) is not int or not 0 <= sample_bytes <= MAX_SAMPLE_BYTES:
        raise ValueError(f"block_entropy {name}.sample_bytes is out of range")
    if type(short_read) is not bool or short_read != (sample_bytes < min(file_size, MAX_SAMPLE_BYTES)):
        raise ValueError(f"block_entropy {name}.short_read is inconsistent")
    lengths = _block_lengths(sample_bytes)
    if not isinstance(entropy, list) or len(entropy) != len(lengths):
        raise ValueError(f"block_entropy {name}.entropy must have one value per block")
    millibits = []
    for item, length in zip(entropy, lengths):
        # A block of n bytes has at most log2(min(n, 256)) bits/byte (rounded as stored).
        ceiling = round(math.log2(min(length, 256)) * _MILLI) / _MILLI
        if type(item) not in {int, float} or not math.isfinite(item) or not 0 <= item <= ceiling:
            raise ValueError(f"block_entropy {name}.entropy values must be possible entropies for their block length")
        scaled = round(item * _MILLI)
        if scaled / _MILLI != item:
            raise ValueError(f"block_entropy {name}.entropy values must have at most three decimals")
        millibits.append(scaled)
    return BlockSample(file_size, sample_bytes, short_read, struct.pack(f"<{len(millibits)}H", *millibits), None)


def _check_statuses(before: BlockSample, after: BlockSample, blocks: list[str]) -> None:
    before_lengths, after_lengths = before.lengths(), after.lengths()
    before_values, after_values = before.entropy_millibits(), after.entropy_millibits()
    if len(blocks) != max(len(before_lengths), len(after_lengths)):
        raise ValueError("blocks must have one status per block index")
    for index, status in enumerate(blocks):
        if index >= len(after_lengths):
            expected = {"before_only"}
        elif index >= len(before_lengths):
            expected = {"after_only"}
        elif before_lengths[index] != after_lengths[index]:
            expected = {"length_changed"}
        elif before_values[index] != after_values[index]:
            expected = {"changed"}  # different entropy cannot be an unchanged block
        else:
            expected = {"changed", "unchanged"}
        if status not in expected:
            raise ValueError(f"block {index} status {status!r} is inconsistent with its measurements")


def block_evidence(before: BlockSample | None, after: BlockSample | None, operation: str,
                   *, before_unmeasured: str | None = None, after_unmeasured: str | None = None) -> BlockEvidence:
    """Combine the baseline and current samples for one event, naming any gap.

    ``*_unmeasured`` gives the reason when a file sample exists but its blocks
    were not measured ("not_measured" or "deferred_under_load"). Without it, a
    missing side means there was no sample at all.
    """
    if before is not None:
        before_missing = None
    else:
        before_missing = before_unmeasured or "not_in_baseline"
    if after is not None:
        after_missing = None
    elif after_unmeasured is not None:
        after_missing = after_unmeasured
    else:
        after_missing = "deleted" if operation == "deleted" else "unreadable"
    return BlockEvidence(before, after, before_missing=before_missing, after_missing=after_missing)
