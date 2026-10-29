"""GameOverlay_InputEventStream_{pid} shared memory (#11446 diagnostics)."""

from __future__ import annotations

import os
import re
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
INPUTEVENT_MAP_SIZES = frozenset({MAP_SIZE_LEGACY, MAP_SIZE_RT64})
DELETED_SUFFIX = " (deleted)"
VULKAN_LAYER_MAP = re.compile(r"steamoverlayvulkanlayer.*\.so", re.I)
HEADER_KIND_OFF = 16  # uint32 == 2 on real InputEvent streams (Wine + native)
INPUTEVENT_HEADER_KIND = 2


@dataclass(frozen=True)
class InputEventShmInfo:
    path: Path
    label: str
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


def _capacity_for_map_size(map_size: int) -> int:
    if map_size == MAP_SIZE_LEGACY:
        return PAYLOAD_BYTES
    if map_size == MAP_SIZE_RT64:
        return PAYLOAD_BYTES
    if map_size > HEADER_BYTES:
        return map_size - HEADER_BYTES
    return PAYLOAD_BYTES


def inputevent_header_valid(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            hdr = f.read(32)
    except OSError:
        return False
    if len(hdr) < HEADER_KIND_OFF + 4:
        return False
    return struct.unpack_from("<I", hdr, HEADER_KIND_OFF)[0] == INPUTEVENT_HEADER_KIND


def _read_write_offset(path: Path) -> int:
    with path.open("rb") as f:
        f.seek(WRITE_CURSOR_OFF)
        return struct.unpack("<I", f.read(4))[0]


def _cursor_plausible(path: Path, map_size: int) -> bool:
    if not inputevent_header_valid(path):
        return False
    try:
        cap = _capacity_for_map_size(map_size)
        off = _read_write_offset(path)
    except OSError:
        return False
    return off <= cap


def _vulkan_layer_mapped(pid: int) -> bool:
    maps = Path(f"/proc/{pid}/maps")
    if not maps.is_file():
        return False
    for line in maps.read_text().splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        pathname = " ".join(parts[5:])
        if pathname.endswith(DELETED_SUFFIX):
            pathname = pathname[: -len(DELETED_SUFFIX)]
        if VULKAN_LAYER_MAP.search(pathname):
            return True
    return False


def _shm_map_lines(pid: int) -> list[tuple[int, str, str]]:
    maps = Path(f"/proc/{pid}/maps")
    if not maps.is_file():
        return []
    out: list[tuple[int, str, str]] = []
    for line in maps.read_text().splitlines():
        if "/dev/shm/" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        start_s, end_s = parts[0].split("-")
        size = int(end_s, 16) - int(start_s, 16)
        name = " ".join(parts[5:]) if len(parts) > 5 else ""
        if name.endswith(DELETED_SUFFIX):
            name = name[: -len(DELETED_SUFFIX)]
        out.append((size, name, parts[1]))
    return out


def _fd_for_shm_size(pid: int, size: int, *, prefer_name: str = "") -> Path | None:
    fd_dir = Path(f"/proc/{pid}/fd")
    if not fd_dir.is_dir():
        return None
    matches: list[tuple[int, Path, str]] = []
    for ent in fd_dir.iterdir():
        if not ent.name.isdigit():
            continue
        proc_fd = Path(f"/proc/{pid}/fd/{ent.name}")
        try:
            link = os.readlink(proc_fd)
            st = proc_fd.stat()
        except OSError:
            continue
        if not link.startswith("/dev/shm/"):
            continue
        if st.st_size != size:
            continue
        matches.append((int(ent.name), proc_fd, link))
    if not matches:
        return None
    if prefer_name:
        for _, proc_fd, link in matches:
            if prefer_name in link or link.endswith(prefer_name):
                return proc_fd
    matches.sort(key=lambda x: x[0])
    return matches[0][1]


def discover_shm_path(pid: int) -> tuple[Path, int, str] | None:
    """Return (readable path, map size, human label). Works for native and Wine/Proton names."""
    needle = f"GameOverlay_InputEventStream_{pid}"
    canonical = path_for_pid(pid)
    if canonical.is_file():
        maps = mapped_sizes_for_pid(pid)
        map_size = maps[0][0] if maps else canonical.stat().st_size
        return canonical, map_size, canonical.name

    scored: list[tuple[int, int, str, str]] = []
    for size, name, perms in _shm_map_lines(pid):
        if size not in INPUTEVENT_MAP_SIZES:
            continue
        if needle in name:
            scored.append((0, size, name, perms))
            continue
        if "GameOverlay_InputEventStream" in name:
            scored.append((1, size, name, perms))
            continue
        if "w" not in perms:
            continue
        # Prefer legacy 524304 (524288 payload + header) over bare 524288 maps.
        rank = 2 if size == MAP_SIZE_LEGACY else 3
        scored.append((rank, size, name, perms))

    scored.sort(key=lambda x: (x[0], x[1]))
    for _, size, name, _ in scored:
        path = Path(name) if name else None
        if path and path.is_file():
            if _cursor_plausible(path, size):
                return path, size, name
        proc_fd = _fd_for_shm_size(pid, size, prefer_name=name.rsplit("/", 1)[-1] if name else "")
        if proc_fd and _cursor_plausible(proc_fd, size):
            try:
                label = f"fd {proc_fd.name} → {os.readlink(proc_fd)}"
            except OSError:
                label = f"fd {proc_fd.name}"
            return proc_fd, size, label

    for size in (MAP_SIZE_LEGACY, MAP_SIZE_RT64):
        proc_fd = _fd_for_shm_size(pid, size)
        if proc_fd and _cursor_plausible(proc_fd, size):
            try:
                label = f"fd {proc_fd.name} → {os.readlink(proc_fd)}"
            except OSError:
                label = f"fd {proc_fd.name}"
            return proc_fd, size, label
    return None


def has_inputevent_shm(pid: int) -> bool:
    return discover_shm_path(pid) is not None


def has_overlay_inputevent_client(pid: int) -> bool:
    """InputEvent SHM on the process that actually hosts the overlay client (not Wine 524304 noise)."""
    found = discover_shm_path(pid)
    if not found:
        return False
    _, _, label = found
    if path_for_pid(pid).is_file() or "GameOverlay_InputEventStream" in label:
        return True
    return _vulkan_layer_mapped(pid)


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
    found = discover_shm_path(pid)
    if not found:
        return None
    path, map_size, label = found
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
        label=label,
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
        f"{indent}InputEvent SHM: {info.label}",
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
        print(
            f"{indent}InputEvent SHM: not found "
            f"(no GameOverlay_InputEventStream_{pid} or 524304/524288 B writable /dev/shm map)"
        )
        return
    for line in format_report(info, brief=brief, indent=indent):
        print(line)
