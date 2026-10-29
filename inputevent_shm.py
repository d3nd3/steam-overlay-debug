"""GameOverlay_InputEventStream_{pid} shared memory (#11446 diagnostics)."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from pathlib import Path

# Mapped size classes seen in the wild (Valve overlay ring + header).
MAP_SIZE_LEGACY = 524304  # 524288 byte ring + 16 byte header
MAP_SIZE_RT64 = 524288  # 0x80000 — payload layout still uses header at start
PAYLOAD_BYTES = 524288  # logical ring capacity (bytes of event stream)
HEADER_BYTES = 16
WRITE_CURSOR_OFF = 4  # uint32 at byte offset 4 (research watch/xxd recipe)


@dataclass(frozen=True)
class InputEventShmInfo:
    path: Path
    map_size: int
    write_offset: int
    payload_capacity: int
    bytes_used_estimate: int
    pct_of_payload: float
    sample_seconds: float
    offset_before: int
    offset_after: int
    delta_bytes: float
    rate_bytes_per_sec: float
    tick_hint: str


def path_for_pid(pid: int) -> Path:
    return Path(f"/dev/shm/GameOverlay_InputEventStream_{pid}")


def mapped_sizes_for_pid(pid: int) -> list[tuple[int, str]]:
    """Return (map_length, maps_line_suffix) for InputEvent SHM in this process."""
    maps = Path(f"/proc/{pid}/maps")
    if not maps.is_file():
        return []
    out: list[tuple[int, str]] = []
    needle = f"GameOverlay_InputEventStream_{pid}"
    for line in maps.read_text().splitlines():
        if needle not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        start_s, end_s = parts[0].split("-")
        size = int(end_s, 16) - int(start_s, 16)
        name = " ".join(parts[5:]) if len(parts) > 5 else ""
        out.append((size, name))
    return out


def _read_write_offset(path: Path) -> int:
    with path.open("rb") as f:
        f.seek(WRITE_CURSOR_OFF)
        return struct.unpack("<I", f.read(4))[0]


def _capacity_for_map_size(map_size: int) -> int:
    if map_size == MAP_SIZE_LEGACY:
        return PAYLOAD_BYTES
    if map_size == MAP_SIZE_RT64:
        return PAYLOAD_BYTES
    if map_size > HEADER_BYTES:
        return map_size - HEADER_BYTES
    return PAYLOAD_BYTES


def _tick_hint(rate: float, offset: int, capacity: int) -> str:
    if rate >= 4.0:
        return "frame tick likely (idle heartbeat ~8 B/s)"
    if rate >= 0.5:
        return "slow creep — tick or light input"
    if offset >= capacity - 256:
        return "near full — #11446 stall risk if tick absent"
    if rate < 0.25 and offset > 0:
        return "idle offset flat — frame tick probably not running"
    return "idle/low activity — check again while not touching input"


def probe_pid(pid: int, *, sample_seconds: float = 1.0) -> InputEventShmInfo | None:
    path = path_for_pid(pid)
    if not path.is_file():
        return None
    maps = mapped_sizes_for_pid(pid)
    map_size = maps[0][0] if maps else path.stat().st_size
    capacity = _capacity_for_map_size(map_size)
    o0 = _read_write_offset(path)
    time.sleep(max(0.1, sample_seconds))
    o1 = _read_write_offset(path)
    dt = sample_seconds
    delta = o1 - o0
    if delta < 0:
        delta = o1  # wrapped / reset toward 0
    rate = delta / dt
    used = min(o1, capacity)
    pct = (100.0 * used / capacity) if capacity else 0.0
    return InputEventShmInfo(
        path=path,
        map_size=map_size,
        write_offset=o1,
        payload_capacity=capacity,
        bytes_used_estimate=used,
        pct_of_payload=pct,
        sample_seconds=dt,
        offset_before=o0,
        offset_after=o1,
        delta_bytes=float(delta),
        rate_bytes_per_sec=rate,
        tick_hint=_tick_hint(rate, o1, capacity),
    )


def format_report(info: InputEventShmInfo, *, brief: bool, indent: str) -> list[str]:
    lines = [
        f"{indent}InputEvent SHM: {info.path.name}",
        f"{indent}  map {info.map_size} B (524304 = 524288 payload + 16 header; 524288 = 0x80000 class)",
        f"{indent}  write cursor @+{WRITE_CURSOR_OFF}: {info.offset_before} → {info.offset_after} "
        f"({info.delta_bytes:+.0f} B in {info.sample_seconds:.1f}s, {info.rate_bytes_per_sec:.1f} B/s)",
        f"{indent}  fill ~{info.bytes_used_estimate}/{info.payload_capacity} B ({info.pct_of_payload:.1f}% of ring)",
        f"{indent}  → {info.tick_hint}",
    ]
    if brief:
        return [lines[0], lines[2], lines[4]]
    return lines


def print_for_pid(pid: int, *, indent: str, brief: bool, sample_seconds: float) -> None:
    info = probe_pid(pid, sample_seconds=sample_seconds)
    if info is None:
        print(f"{indent}InputEvent SHM: not found (/dev/shm/GameOverlay_InputEventStream_{pid})")
        return
    for line in format_report(info, brief=brief, indent=indent):
        print(line)
