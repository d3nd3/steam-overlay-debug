#!/usr/bin/env python3
"""Linux: list gameoverlayrenderer.so mappings in a game process and report build ids."""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from version import OverlayVersion, analyze_bytes

from inputevent_shm import (
    discover_shm_path,
    has_overlay_inputevent_client,
    path_for_pid,
    print_for_pid as print_inputevent_shm,
)
from vulkan_layer_manifest import format_manifest_lines, steam_overlay_manifests

OVERLAY_MAP = re.compile(r"gameoverlayrenderer.*\.so", re.I)
VULKAN_LAYER_MAP = re.compile(r"steamoverlayvulkanlayer.*\.so", re.I)
DELETED_SUFFIX = " (deleted)"
LAUNCHER_COMMS = frozenset({"sh", "bash", "dash", "steam-launch-wrapper", "reaper"})
GAME_COMMS = frozenset({"dota2", "cs2", "GameThread", "hl2_linux", "dota.sh"})
SKIP_COMMS = frozenset(
    {"python3", "python", "sleep", "cat", "grep", "bash", "sh", "reaper", "steam-launch-wrapper"}
)
WINE_OVERLAY_HELPER = frozenset(
    {
        "steam.exe",
        "wineserver",
        "services.exe",
        "winedevice.exe",
        "svchost.exe",
        "plugplay.exe",
        "lsass.exe",
        "rpcss.exe",
        "tabtip.exe",
        "python3",
    }
)


@dataclass(frozen=True)
class LoadedOverlay:
    pid: int
    vma: str
    perms: str
    pathname: str
    deleted: bool
    inode: int
    dev: str
    read_path: Path


def _proc_cmdline(pid: int) -> str:
    raw = (Path(f"/proc/{pid}/cmdline").read_bytes()).replace(b"\x00", b" ").strip()
    return raw.decode("utf-8", "replace")


def _proc_environ(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/environ").read_bytes()
    return [e.decode("utf-8", "replace") for e in raw.split(b"\x00") if e]


def _layer_env_lines(pid: int) -> list[str]:
    """Overlay / Vulkan implicit-layer related variables (full NAME=value lines)."""
    out: list[str] = []
    for line in _proc_environ(pid):
        if (
            line.startswith("SteamNoOverlayUI=")
            or (line.startswith("ENABLE_VK_LAYER") and "=" in line)
            or (line.startswith("DISABLE_VK_LAYER") and "=" in line)
            or line.startswith("PRESSURE_VESSEL_REMOVE_GAME_OVERLAY=")
            or line.startswith("PRESSURE_VESSEL_IMPORT_VULKAN_LAYERS=")
            or line.startswith("VK_IMPLICIT_LAYER_PATH=")
            or line.startswith("VK_LAYER_PATH=")
        ):
            out.append(line)
    return sorted(set(out))


def _vulkan_layer_map_paths(pid: int) -> list[str]:
    maps = Path(f"/proc/{pid}/maps")
    if not maps.is_file():
        return []
    seen: set[str] = set()
    out: list[str] = []
    for line in maps.read_text().splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        pathname = " ".join(parts[5:])
        if pathname.endswith(DELETED_SUFFIX):
            pathname = pathname[: -len(DELETED_SUFFIX)]
        if VULKAN_LAYER_MAP.search(pathname) and pathname not in seen:
            seen.add(pathname)
            out.append(pathname)
    return sorted(out)


VULKAN_LOADER_MAP = re.compile(r"libvulkan\.so", re.I)
EGL_MAP = re.compile(r"libEGL\.so", re.I)
OPENGL_MAP = re.compile(r"lib(?:GL|OpenGL)\.so", re.I)
WINE_D3D_MAP = re.compile(r"(?:wined3d|d3d11|dxgi)", re.I)
WEBKIT_MAP = re.compile(r"libwebkit2?gtk|JavaScriptCore|libWTF-", re.I)
CEF_MAP = re.compile(r"libcef\.so|libcef_dll|/cef/libcef", re.I)
ANGLE_MAP = re.compile(r"libEGL.*angle|libGLES.*angle|libangle\.so", re.I)
SDL_MAP = re.compile(r"libSDL2?-\d*\.so", re.I)


def _graphics_apis_in_maps(maps: str) -> list[str]:
    apis: list[str] = []
    if VULKAN_LOADER_MAP.search(maps) or VULKAN_LAYER_MAP.search(maps):
        apis.append("Vulkan")
    if EGL_MAP.search(maps):
        apis.append("EGL")
    if OPENGL_MAP.search(maps):
        apis.append("OpenGL")
    if WINE_D3D_MAP.search(maps):
        apis.append("Direct3D (Wine)")
    if WEBKIT_MAP.search(maps):
        apis.append("WebKit")
    if CEF_MAP.search(maps):
        apis.append("CEF/Chromium")
    if ANGLE_MAP.search(maps):
        apis.append("ANGLE")
    if SDL_MAP.search(maps):
        apis.append("SDL2")
    if ("WebKit" in apis or "CEF/Chromium" in apis) and ("OpenGL" in apis or "EGL" in apis):
        apis.append("WebGL (browser engine + GL/EGL)")
    return apis


def _overlay_graphics_report(pid: int) -> tuple[str, str, list[str]]:
    """Overlay injection path + graphics libraries visible in /proc/pid/maps."""
    try:
        maps = Path(f"/proc/{pid}/maps").read_text()
        envs = _proc_environ(pid)
    except OSError:
        return "unknown", "could not read process maps or environment", []
    apis = _graphics_apis_in_maps(maps)
    vk_paths = _vulkan_layer_map_paths(pid)
    vk_enabled = any(
        line.startswith("ENABLE_VK_LAYER_VALVE_steam_overlay_1=")
        and line.split("=", 1)[1].strip() not in ("0", "")
        for line in envs
    )
    has_renderer = bool(overlay_mappings(pid))
    manifests = steam_overlay_manifests(pid, envs)
    active_manifest = next(
        (m for m in manifests if m.library_mapped or (m.loader_enabled and not m.loader_disabled)),
        None,
    )

    if vk_paths and (vk_enabled or (active_manifest and active_manifest.library_mapped)):
        detail = "steamoverlayvulkanlayer.so mapped"
        if active_manifest:
            detail += f"; manifest {active_manifest.json_path.name}"
            if active_manifest.loader_enabled:
                detail += ", enable_environment met"
            elif active_manifest.library_mapped:
                detail += ", loaded without enable_environment"
        elif vk_enabled:
            detail += "; ENABLE_VK_LAYER_VALVE_steam_overlay set"
        if has_renderer:
            detail += "; gameoverlayrenderer.so preloaded"
        return "Vulkan (Steam overlay layer)", detail, apis
    if vk_paths:
        return (
            "Vulkan (layer mapped, overlay env off)",
            "steamoverlayvulkanlayer.so in maps; ENABLE_VK_LAYER_VALVE_steam_overlay not set",
            apis,
        )
    if has_renderer and ("OpenGL" in apis or "EGL" in apis):
        return (
            "OpenGL (gameoverlayrenderer preload)",
            "no steamoverlayvulkanlayer.so; hook via preloaded gameoverlayrenderer.so",
            apis,
        )
    if has_renderer and "Direct3D (Wine)" in apis:
        return (
            "Direct3D via Wine (gameoverlayrenderer preload)",
            "no Vulkan overlay layer in maps; gameoverlayrenderer.so preloaded",
            apis,
        )
    if has_renderer:
        return (
            "gameoverlayrenderer.so only",
            "overlay .so mapped; injection API not identified",
            apis,
        )
    return "unknown", "no overlay libraries in maps", apis


def _print_layer_vulkan_status(pid: int, *, indent: str, brief: bool) -> None:
    try:
        envs = _layer_env_lines(pid)
        layers = _vulkan_layer_map_paths(pid)
    except (OSError, PermissionError):
        print(f"{indent}layer/vulkan: (cannot read environ/maps)")
        return
    if layers:
        if brief:
            tail = Path(layers[0]).name
            extra = f" (+{len(layers) - 1} more)" if len(layers) > 1 else ""
            print(f"{indent}steamoverlayvulkanlayer.so: mapped · {tail}{extra}")
        else:
            print(f"{indent}steamoverlayvulkanlayer.so: mapped")
            for p in layers:
                print(f"{indent}  {p}")
    else:
        print(f"{indent}steamoverlayvulkanlayer.so: not in maps")
    if envs:
        print(f"{indent}layer env ({len(envs)}):")
        for line in envs:
            if brief and len(line) > 100:
                print(f"{indent}  {line[:99]}…")
            else:
                print(f"{indent}  {line}")
    else:
        print(f"{indent}layer env: (no ENABLE/DISABLE_VK_LAYER, SteamNoOverlayUI, or VK_IMPLICIT_LAYER_PATH)")
    if not brief:
        try:
            full_env = _proc_environ(pid)
        except OSError:
            full_env = []
        for line in format_manifest_lines(
            steam_overlay_manifests(pid, full_env), indent=indent, pid=pid
        ):
            print(line)


def _proc_comm(pid: int) -> str:
    return Path(f"/proc/{pid}/comm").read_text().strip()


def _process_role(comm: str, cmdline: str, *, pid: int | None = None) -> str:
    if comm in LAUNCHER_COMMS or "steam-launch-wrapper" in cmdline or " reaper " in cmdline:
        return "launcher"
    if pid is not None and has_overlay_inputevent_client(pid):
        return "game"
    if comm in GAME_COMMS or re.search(
        r"steamapps/common/|AppId=\d+|\.steam/.*?/game/", cmdline
    ):
        if comm not in LAUNCHER_COMMS:
            return "game"
    return "other"


@dataclass(frozen=True)
class OverlaySnap:
    pid: int
    comm: str
    build_id: str
    sha256: str
    pathname: str
    deploy: str | None


def _launch_hints(cmdline: str) -> tuple[str | None, list[str]]:
    app_m = re.search(r"AppId=(\d+)", cmdline)
    app_id = app_m.group(1) if app_m else None
    hints: list[str] = []
    if app_id:
        hints.append(f"AppId={app_id}")
    gm = re.search(r"steamapps/common/([^'\"]+)", cmdline)
    if gm:
        hints.append(gm.group(1).strip().rstrip("/"))
    for token in ("dota.sh", "dota2", "cs2", "hl2_linux"):
        if token in cmdline:
            hints.append(token)
    return app_id, hints


def _candidate_game_pids(hints: list[str], *, exclude: set[int]) -> list[int]:
    if not hints:
        return []
    app_hint = next((h for h in hints if h.startswith("AppId=")), None)
    path_hints = [h for h in hints if not h.startswith("AppId=")]
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in exclude:
            continue
        try:
            comm = _proc_comm(pid)
            cmd = _proc_cmdline(pid)
        except (OSError, PermissionError):
            continue
        if _process_role(comm, cmd, pid=pid) == "launcher" or comm in SKIP_COMMS:
            continue
        if comm in GAME_COMMS:
            if app_hint and app_hint not in cmd and "steamapps/common" not in cmd:
                if comm not in ("dota2", "cs2"):
                    continue
            found.append(pid)
            continue
        if path_hints and any(h in cmd for h in path_hints):
            if comm in {"srt-bwrap", "pv-adverb"}:
                continue
            if comm in GAME_COMMS or comm.endswith(".sh"):
                found.append(pid)
    return sorted(set(found))


def _overlay_pids_excluding(exclude: set[int]) -> list[int]:
    return [
        pid
        for pid in pids_with_overlay_loaded(include_launchers=False)
        if pid not in exclude
    ]


def _snapshots_for_pid(pid: int) -> list[OverlaySnap]:
    comm = _proc_comm(pid)
    out: list[OverlaySnap] = []
    for ent in unique_overlays(overlay_mappings(pid)):
        try:
            info = analyze_loaded(ent)
        except (OSError, ValueError):
            continue
        bid = info.gnu_build_id or info.sha256
        out.append(
            OverlaySnap(
                pid=pid,
                comm=comm,
                build_id=bid,
                sha256=info.sha256,
                pathname=ent.pathname,
                deploy=info.deploy_path,
            )
        )
    return out


def _short_build_id(build_id: str) -> str:
    return build_id[:8] if len(build_id) > 8 else build_id


def _overlay_slot_english(deploy: str | None) -> str:
    if deploy == "ubuntu12_32":
        return "32-bit client overlay"
    if deploy == "ubuntu12_64":
        return "64-bit client overlay"
    if deploy:
        return f"{deploy} overlay"
    return "client overlay"


def _group_pids_by_overlay_build(
    pids: list[int],
) -> dict[str, tuple[str | None, list[tuple[str, int]]]]:
    groups: dict[str, tuple[str | None, list[tuple[str, int]]]] = {}
    for gpid in pids:
        gs = _snapshots_for_pid(gpid)
        if len(gs) != 1:
            continue
        g = gs[0]
        try:
            comm = _proc_comm(gpid)
        except OSError:
            continue
        if g.build_id not in groups:
            groups[g.build_id] = (g.deploy, [])
        groups[g.build_id][1].append((comm, gpid))
    return groups


def _describe_proc_group(procs: list[tuple[str, int]]) -> str:
    procs = sorted(procs, key=lambda x: x[1])
    if len(procs) == 1:
        c, p = procs[0]
        return f"{c} (pid {p})"
    players = [p for p in procs if p[0] not in WINE_OVERLAY_HELPER]
    helpers = [p for p in procs if p[0] in WINE_OVERLAY_HELPER]
    if len(players) == 1 and helpers:
        c, p = players[0]
        n = len(helpers)
        tail = f"{n} Proton/Wine helper process{'es' if n != 1 else ''}"
        return f"{c} (pid {p}) and {tail}"
    if players and not helpers:
        if len(players) <= 2:
            return " and ".join(f"{c} (pid {p})" for c, p in players)
        return f"{len(players)} game-related processes"
    if helpers and not players:
        n = len(helpers)
        return f"{n} Proton/Wine helper process{'es' if n != 1 else ''}"
    return f"{len(procs)} processes"


def _overlay_build_phrase(deploy: str | None, build_id: str) -> str:
    return f"{_overlay_slot_english(deploy)} ({_short_build_id(build_id)}…)"


def _launcher_overlay_summary(
    launcher_pid: int,
    launcher_snaps: list[OverlaySnap],
    other_pids: list[int],
) -> str:
    launch = launcher_snaps[0]
    launcher_ids = {s.build_id for s in launcher_snaps}
    try:
        shell = f"{_proc_comm(launcher_pid)} (pid {launcher_pid})"
    except OSError:
        shell = f"pid {launcher_pid}"
    groups = _group_pids_by_overlay_build(other_pids)
    matching: list[tuple[str, int]] = []
    other: list[tuple[str, str | None, list[tuple[str, int]]]] = []
    for bid, (dep, procs) in groups.items():
        if bid in launcher_ids:
            matching.extend(procs)
        else:
            other.append((bid, dep, procs))

    parts = [
        f"{shell} loaded {_overlay_build_phrase(launch.deploy, launch.build_id)}.",
    ]
    if matching:
        parts.append(f"The same build is mapped in {_describe_proc_group(matching)}.")
    elif groups:
        parts.append("No other running process in this scan uses that build.")
    for bid, dep, procs in other:
        verb = "maps" if len(procs) == 1 else "map"
        parts.append(
            f"{_describe_proc_group(procs)} {verb} {_overlay_build_phrase(dep, bid)}."
        )
    return " ".join(parts)


def _session_overlay_pids(*, exclude: set[int]) -> list[int]:
    out: list[int] = []
    for pid in _overlay_pids_excluding(exclude=exclude):
        try:
            if _proc_comm(pid) in SKIP_COMMS:
                continue
        except OSError:
            continue
        if has_overlay_inputevent_client(pid):
            out.append(pid)
    return sorted(out)


def _print_launcher_game_check(
    launcher_pid: int,
    launcher_cmd: str,
    launcher_snaps: list[OverlaySnap],
) -> None:
    app_id, hints = _launch_hints(launcher_cmd)
    if not hints:
        print("  Could not parse AppId or game path from this launch shell.")
        return

    launcher_ids = {s.build_id for s in launcher_snaps}
    game_pids = _candidate_game_pids(hints, exclude={launcher_pid})
    other_pids = _session_overlay_pids(exclude={launcher_pid})

    if not game_pids and not other_pids:
        print("  No matching game process in /proc (game not running yet?).")
        return

    if launcher_snaps and other_pids:
        print(f"  {_launcher_overlay_summary(launcher_pid, launcher_snaps, other_pids)}")

    game_snaps = [g for gpid in game_pids for g in _snapshots_for_pid(gpid)]

    if game_pids and not game_snaps:
        if 'LD_PRELOAD=""' in launcher_cmd or "LD_PRELOAD=''" in launcher_cmd:
            print(
                "  Note: this launch shell clears LD_PRELOAD; overlay mapped here "
                "does not mean the game inherited the same preload."
            )
        if app_id == "570" or "dota" in launcher_cmd.lower():
            print(
                "  Note: Dota on linuxsteamrt64 normally maps the steamrt64 overlay "
                "in the game process when injection works; ubuntu12_64 on the shell "
                "alone matches the missing-frame-tick case in CLARITY.md."
            )
        print(
            "  Game processes are running but none map gameoverlayrenderer.so; "
            "the preload on this shell does not apply inside the game."
        )
        if other_pids:
            print("  Other processes in this session still map the overlay (see summary above).")
        return

    if game_snaps and all(g.build_id in launcher_ids for g in game_snaps):
        print("  The game process uses the same overlay build as this launch shell.")
    elif game_snaps:
        print("  The game process uses a different overlay build than this launch shell.")


def _parse_maps_line(pid: int, line: str) -> LoadedOverlay | None:
    parts = line.split()
    if len(parts) < 5:
        return None
    pathname = " ".join(parts[5:]) if len(parts) > 5 else ""
    if not pathname or not OVERLAY_MAP.search(pathname):
        return None
    deleted = pathname.endswith(DELETED_SUFFIX)
    if deleted:
        pathname = pathname[: -len(DELETED_SUFFIX)]
    vma = parts[0]
    map_file = Path(f"/proc/{pid}/map_files/{vma}")
    read_path = map_file if map_file.exists() else Path(pathname)
    return LoadedOverlay(
        pid=pid,
        vma=vma,
        perms=parts[1],
        pathname=pathname,
        deleted=deleted,
        inode=int(parts[4]),
        dev=parts[3],
        read_path=read_path,
    )


def overlay_mappings(pid: int) -> list[LoadedOverlay]:
    maps = Path(f"/proc/{pid}/maps")
    if not maps.is_file():
        raise FileNotFoundError(f"no such process: {pid}")
    out: list[LoadedOverlay] = []
    for line in maps.read_text().splitlines():
        ent = _parse_maps_line(pid, line)
        if ent:
            out.append(ent)
    return out


def unique_overlays(entries: list[LoadedOverlay]) -> list[LoadedOverlay]:
    by_inode: dict[tuple[str, int], LoadedOverlay] = {}
    for e in entries:
        key = (e.dev, e.inode)
        if key not in by_inode or "x" in e.perms:
            by_inode[key] = e
    return list(by_inode.values())


def pids_matching(*, comm: str | None, cmdline: re.Pattern[str] | None) -> list[int]:
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            if comm and _proc_comm(pid) != comm:
                continue
            if cmdline and not cmdline.search(_proc_cmdline(pid)):
                continue
        except (OSError, PermissionError):
            continue
        found.append(pid)
    return sorted(found)


def pids_with_overlay_loaded(*, include_launchers: bool) -> list[int]:
    hits: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            if not overlay_mappings(pid):
                continue
            if not include_launchers:
                comm = _proc_comm(pid)
                cmd = _proc_cmdline(pid)
                if _process_role(comm, cmd, pid=pid) == "launcher":
                    continue
            hits.append(pid)
        except (OSError, PermissionError, FileNotFoundError):
            continue
    return hits


def pids_for_scan() -> tuple[list[int], bool]:
    """Prefer InputEvent SHM clients; else fall back to any gameoverlayrenderer.so mapping."""
    shm: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            if not overlay_mappings(pid):
                continue
        except (OSError, PermissionError, FileNotFoundError):
            continue
        if has_overlay_inputevent_client(pid):
            shm.append(pid)
    if shm:
        return sorted(set(shm)), True
    overlay = pids_with_overlay_loaded(include_launchers=False)
    if overlay:
        return overlay, False
    return pids_with_overlay_loaded(include_launchers=True), False


def analyze_loaded(entry: LoadedOverlay) -> OverlayVersion:
    try:
        data = entry.read_path.read_bytes()
    except OSError as e:
        raise OSError(f"cannot read mapped file {entry.read_path}: {e}") from e
    return analyze_bytes(data, Path(entry.pathname), hint_path=entry.pathname)


@dataclass(frozen=True)
class ScanRow:
    pid: int
    comm: str
    role: str
    cmd: str
    ent: LoadedOverlay
    info: OverlayVersion


def _cmd_short(cmd: str, n: int = 160) -> str:
    return cmd if len(cmd) <= n else cmd[: n - 1] + "…"


def print_build_spec(
    ent: LoadedOverlay,
    info: OverlayVersion,
    *,
    online_lookup: bool,
    live: bool,
) -> None:
    base = Path(ent.pathname).name
    tag = " (deleted from disk)" if ent.deleted else ""
    print(f"  [{base}]{tag}")
    print(f"  Version: {info.version}")
    for line in info.proc_summary():
        print(line)
    if info.debug_link:
        print(f"  Debug link: {info.debug_link}")
    print(f"  Path: {ent.pathname}")
    if online_lookup:
        try:
            print_online_lookup(
                ent.read_path.read_bytes(),
                info.gnu_build_id,
                brief=False,
                live=live,
                manifest_relpath=(
                    f"{info.deploy_path}/gameoverlayrenderer.so" if info.deploy_path else None
                ),
                overlay_path=ent.pathname,
            )
        except OSError:
            pass


def _gather_scan_rows(pids: list[int]) -> list[ScanRow]:
    rows: list[ScanRow] = []
    for pid in pids:
        try:
            mappings = unique_overlays(overlay_mappings(pid))
        except (OSError, PermissionError, FileNotFoundError):
            continue
        if not mappings:
            continue
        comm = _proc_comm(pid)
        cmd = _proc_cmdline(pid)
        role = _process_role(comm, cmd, pid=pid)
        for ent in mappings:
            try:
                info = analyze_loaded(ent)
            except (OSError, ValueError):
                continue
            rows.append(ScanRow(pid=pid, comm=comm, role=role, cmd=cmd, ent=ent, info=info))
    return rows


def _game_renderer_rows(rows: list[ScanRow]) -> list[ScanRow]:
    """Overlay build mapped in the live game client (InputEvent SHM), one row per pid."""
    picked: dict[int, ScanRow] = {}
    for r in rows:
        if r.comm in LAUNCHER_COMMS:
            continue
        if not has_overlay_inputevent_client(r.pid):
            continue
        picked.setdefault(r.pid, r)
    if picked:
        return sorted(picked.values(), key=lambda x: x.pid)
    for r in rows:
        if r.role != "game" or r.comm in LAUNCHER_COMMS:
            continue
        picked.setdefault(r.pid, r)
    return sorted(picked.values(), key=lambda x: x.pid)


def _print_renderer_detection(r: ScanRow, *, indent: str, brief: bool) -> None:
    phrase = _overlay_build_phrase(r.info.deploy_path, r.info.gnu_build_id or r.info.sha256)
    injection, inj_detail, apis = _overlay_graphics_report(r.pid)
    api_line = ", ".join(apis) if apis else "none matched in /proc/maps"
    if brief:
        print(f"{indent}Renderer: {phrase} · injection {injection} · APIs {api_line}")
        return
    print(f"{indent}Renderer build: {phrase}")
    print(f"{indent}  Overlay injection: {injection} — {inj_detail}")
    print(f"{indent}  Graphics APIs in process: {api_line}")
    print(f"{indent}  Why this process is the overlay client:")
    print(f"{indent}  · gameoverlayrenderer.so mapped (see build block above)")
    found = discover_shm_path(r.pid)
    if found:
        _, size, _ = found
        print(f"{indent}  · InputEvent ring mapped ({size} bytes)")
    if path_for_pid(r.pid).is_file():
        print(f"{indent}  · canonical GameOverlay_InputEventStream_{r.pid} shared memory")
    elif _vulkan_layer_map_paths(r.pid):
        print(f"{indent}  · Proton/Wine renames the ring to u1000-Shm_* (fd path shown below)")
    elif found and "GameOverlay_InputEventStream" in found[2]:
        print(f"{indent}  · GameOverlay_InputEventStream name in /proc/maps")


def _print_scan_launch_summary(rows: list[ScanRow]) -> None:
    games = [r for r in rows if r.role == "game"]
    launchers = [r for r in rows if r.role == "launcher"]
    if not games and not launchers:
        return
    print("=== Overlay summary ===")
    if games:
        by_sha: dict[str, list[ScanRow]] = defaultdict(list)
        for g in games:
            by_sha[g.info.sha256].append(g)
        for sha, grp in by_sha.items():
            r0 = grp[0]
            names = ", ".join(f"{r.comm} pid {r.pid}" for r in sorted(grp, key=lambda x: x.pid))
            print(
                f"  Game {names}: {_overlay_build_phrase(r0.info.deploy_path, r0.info.gnu_build_id or sha)}"
            )
    launcher_pids = {lr.pid for lr in launchers}
    session_pids = _session_overlay_pids(exclude=launcher_pids)
    for lr in sorted(launchers, key=lambda x: x.pid):
        game_sha = games[0].info.sha256 if games else None
        if game_sha and lr.info.sha256 == game_sha:
            print(f"  {lr.comm} (pid {lr.pid}): same overlay build as the game process")
        elif games:
            g0 = games[0]
            print(
                f"  {lr.comm} (pid {lr.pid}): {_overlay_build_phrase(lr.info.deploy_path, lr.info.gnu_build_id or lr.info.sha256)} "
                f"— the game uses {_overlay_build_phrase(g0.info.deploy_path, g0.info.gnu_build_id or g0.info.sha256)} "
                "(often an unused 32-bit preload on the reaper step)"
            )
        elif session_pids:
            snaps = [
                OverlaySnap(
                    pid=lr.pid,
                    comm=lr.comm,
                    build_id=lr.info.gnu_build_id or lr.info.sha256,
                    sha256=lr.info.sha256,
                    pathname=lr.ent.pathname,
                    deploy=lr.info.deploy_path,
                )
            ]
            print(f"  {_launcher_overlay_summary(lr.pid, snaps, session_pids)}")
    print()


def print_scan_deduped(
    pids: list[int],
    *,
    brief: bool,
    live: bool,
    shm_sample_sec: float,
    no_shm: bool,
    shm_clients: bool = True,
) -> bool:
    rows = _gather_scan_rows(pids)
    if not rows:
        return False
    by_sha: dict[str, list[ScanRow]] = defaultdict(list)
    for row in rows:
        by_sha[row.info.sha256].append(row)

    n_proc = len({r.pid for r in rows})
    if shm_clients:
        print(f"=== {len(by_sha)} overlay build(s) · {n_proc} InputEvent SHM client(s) ===\n")
    else:
        print(
            f"=== {len(by_sha)} overlay build(s) · {n_proc} process(es) "
            f"mapping gameoverlayrenderer.so ===\n"
        )
        print("  No InputEvent SHM client matched; listing all renderer mappings.\n")
    game_shas = {r.info.sha256 for r in _game_renderer_rows(rows)}
    for idx, sha in enumerate(sorted(by_sha.keys()), 1):
        group = sorted(by_sha[sha], key=lambda r: (r.info.deploy_path or "", r.pid))
        sample = group[0]
        dep = sample.info.deploy_path or "?"
        in_use = " · used by game" if sha in game_shas else ""
        print(f"--- build {idx}/{len(by_sha)} · {dep} · Build ID {sample.info.gnu_build_id}{in_use} ---")
        if brief:
            fp = sample.info.fingerprint or "—"
            print(f"  fingerprint {fp}  sha256 {sample.info.sha256[:16]}…")
        else:
            print_build_spec(
                sample.ent,
                sample.info,
                online_lookup=True,
                live=live,
            )
        print("  Mapped in:")
        layer_done: set[int] = set()
        for r in group:
            vma = r.ent.vma
            perms = r.ent.perms
            if brief:
                print(f"    pid {r.pid} · {r.comm} · {r.role} · {vma}")
            else:
                print(f"    pid {r.pid} · {r.comm} · {r.role} · map {vma} {perms}")
                print(f"      cmd: {_cmd_short(r.cmd)}")
            if r.pid not in layer_done:
                layer_done.add(r.pid)
                _print_renderer_detection(r, indent="      ", brief=brief)
                _print_layer_vulkan_status(r.pid, indent="      ", brief=brief)
                if not no_shm:
                    print_inputevent_shm(
                        r.pid, indent="      ", brief=brief, sample_seconds=shm_sample_sec
                    )
        print()

    return True


def print_online_lookup(
    data: bytes,
    gnu_build_id: str | None,
    *,
    brief: bool,
    live: bool,
    manifest_relpath: str | None = None,
    overlay_path: str | None = None,
) -> None:
    from online_lookup import lookup_binary

    rep = lookup_binary(
        data,
        gnu_build_id=gnu_build_id,
        manifest_relpath=manifest_relpath,
        overlay_path=overlay_path,
        live=live,
    )
    if not rep.hits:
        return
    if brief:
        for h in rep.hits:
            d = h.detail or h.source
            print(f"           online: {d}")
        return
    for line in rep.lines():
        print(line)


def print_overlay_block(
    ent: LoadedOverlay,
    info: OverlayVersion,
    *,
    brief: bool,
    online_lookup: bool = False,
    live: bool = True,
) -> None:
    base = Path(ent.pathname).name
    tag = " (deleted from disk)" if ent.deleted else ""
    print(f"  [{base}]{tag}")
    print(f"  Version: {info.version}")
    if brief:
        fp = info.fingerprint or "—"
        dep = info.deploy_path or "—"
        print(f"           fingerprint {fp}  deploy {dep}")
        if online_lookup:
            try:
                print_online_lookup(
                    ent.read_path.read_bytes(),
                    info.gnu_build_id,
                    brief=True,
                    live=live,
                    manifest_relpath=(
                        f"{info.deploy_path}/gameoverlayrenderer.so" if info.deploy_path else None
                    ),
                    overlay_path=ent.pathname,
                )
            except OSError:
                pass
        return
    for line in info.proc_summary(vma=ent.vma, perms=ent.perms):
        print(line)
    if info.debug_link:
        print(f"  Debug link: {info.debug_link}")
    print(f"  Path: {ent.pathname}")
    if online_lookup:
        try:
            print_online_lookup(
                ent.read_path.read_bytes(),
                info.gnu_build_id,
                brief=brief,
                live=live,
                manifest_relpath=(
                    f"{info.deploy_path}/gameoverlayrenderer.so" if info.deploy_path else None
                ),
                overlay_path=ent.pathname,
            )
        except OSError:
            pass


def print_process_report(
    pid: int,
    *,
    brief: bool,
    show_launchers: bool,
    online_lookup: bool = False,
    live: bool = True,
    shm_sample_sec: float = 1.0,
    no_shm: bool = False,
) -> bool:
    try:
        mappings = unique_overlays(overlay_mappings(pid))
    except FileNotFoundError:
        print(f"pid {pid}: not found", file=sys.stderr)
        return False
    except PermissionError:
        print(f"pid {pid}: permission denied (try same user or root)", file=sys.stderr)
        return False

    comm = _proc_comm(pid)
    cmd = _proc_cmdline(pid)
    role = _process_role(comm, cmd, pid=pid)

    if not mappings:
        print(f"pid {pid} ({comm}): no gameoverlayrenderer.so mapped")
        return True

    if role == "launcher" and not show_launchers:
        return True

    header = f"--- pid {pid} · {comm} · {role} ---"
    print(header)
    if not brief:
        print(f"  cmdline: {cmd[:200]}{'…' if len(cmd) > 200 else ''}")

    launcher_snaps: list[OverlaySnap] = []
    for ent in sorted(mappings, key=lambda x: x.pathname):
        try:
            info = analyze_loaded(ent)
        except (OSError, ValueError) as e:
            print(f"  error: {ent.pathname}: {e}")
            continue
        print_overlay_block(
            ent,
            info,
            brief=brief,
            online_lookup=online_lookup,
            live=live,
        )
        if role == "launcher":
            launcher_snaps.append(
                OverlaySnap(
                    pid=pid,
                    comm=comm,
                    build_id=info.gnu_build_id or info.sha256,
                    sha256=info.sha256,
                    pathname=ent.pathname,
                    deploy=info.deploy_path,
                )
            )

    _print_layer_vulkan_status(pid, indent="  ", brief=brief)
    if not no_shm:
        print_inputevent_shm(pid, indent="  ", brief=brief, sample_seconds=shm_sample_sec)

    if role == "launcher" and launcher_snaps and not brief:
        _print_launcher_game_check(pid, cmd, launcher_snaps)
    print()
    return True


def print_scan_preamble(*, games_only: bool) -> None:
    if games_only:
        print(
            "Listing processes with InputEvent SHM (game client); "
            "launcher preloads hidden.\n"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Steam overlay debugger (#11446): renderer builds in /proc, Vulkan layer env/maps, "
            "GameOverlay_InputEventStream SHM growth."
        ),
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pid", type=int, metavar="PID", help="Process id")
    g.add_argument("--comm", metavar="NAME", help="Exact /proc/pid/comm (e.g. dota2)")
    g.add_argument(
        "--cmdline",
        metavar="REGEX",
        help="Python regex matched against the process cmdline",
    )
    g.add_argument(
        "--scan",
        action="store_true",
        help="Prefer InputEvent SHM clients; else list gameoverlayrenderer.so mappings",
    )
    ap.add_argument(
        "--games-only",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    ap.add_argument("--include-launchers", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument(
        "-q",
        "--brief",
        action="store_true",
        help="One-line summary per mapped .so",
    )
    ap.add_argument(
        "--no-live",
        action="store_true",
        help="With --scan, skip SteamTracking/debuginfod HTTP checks",
    )
    ap.add_argument(
        "--shm-sample-sec",
        type=float,
        default=2.0,
        metavar="SEC",
        help="Seconds to watch InputEvent write cursor for frame-loop heuristic (default 2)",
    )
    ap.add_argument(
        "--no-shm",
        action="store_true",
        help="Skip GameOverlay_InputEventStream_* sampling",
    )
    args = ap.parse_args(argv)

    if args.scan:
        pids, shm_clients = pids_for_scan()
        if not pids:
            print(
                "No process maps gameoverlayrenderer.so.",
                file=sys.stderr,
            )
            return 1
        ok = print_scan_deduped(
            pids,
            brief=args.brief,
            live=not args.no_live,
            shm_sample_sec=args.shm_sample_sec,
            no_shm=args.no_shm,
            shm_clients=shm_clients,
        )
        return 0 if ok else 1

    if args.pid is not None:
        pids = [args.pid]
    elif args.comm:
        pids = pids_matching(comm=args.comm, cmdline=None)
    else:
        pids = pids_matching(comm=None, cmdline=re.compile(args.cmdline))

    if not pids:
        print("No matching process.", file=sys.stderr)
        return 1

    ok = True
    for pid in pids:
        ok = print_process_report(
            pid,
            brief=args.brief,
            show_launchers=True,
            shm_sample_sec=args.shm_sample_sec,
            no_shm=args.no_shm,
        ) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
