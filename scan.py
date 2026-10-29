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

OVERLAY_MAP = re.compile(r"gameoverlayrenderer.*\.so", re.I)
VULKAN_LAYER_MAP = re.compile(r"steamoverlayvulkanlayer.*\.so", re.I)
DELETED_SUFFIX = " (deleted)"
LAUNCHER_COMMS = frozenset({"sh", "bash", "dash", "steam-launch-wrapper", "reaper"})
GAME_COMMS = frozenset({"dota2", "cs2", "GameThread", "hl2_linux", "dota.sh"})
SKIP_COMMS = frozenset(
    {"python3", "python", "sleep", "cat", "grep", "bash", "sh", "reaper", "steam-launch-wrapper"}
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


from inputevent_shm import print_for_pid as print_inputevent_shm


def _proc_comm(pid: int) -> str:
    return Path(f"/proc/{pid}/comm").read_text().strip()


def _process_role(comm: str, cmdline: str) -> str:
    if comm in GAME_COMMS or re.search(
        r"steamapps/common/|AppId=\d+|\.steam/.*?/game/", cmdline
    ):
        if comm not in LAUNCHER_COMMS:
            return "game"
    if comm in LAUNCHER_COMMS or "steam-launch-wrapper" in cmdline or " reaper " in cmdline:
        return "launcher"
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
        if _process_role(comm, cmd) == "launcher" or comm in SKIP_COMMS:
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


def _print_launcher_game_check(
    launcher_pid: int,
    launcher_cmd: str,
    launcher_snaps: list[OverlaySnap],
) -> None:
    app_id, hints = _launch_hints(launcher_cmd)
    label = ", ".join(repr(h) for h in hints) if hints else "cmdline"
    print(f"  Game check (hints: {label}):")
    if not hints:
        print("    Could not parse AppId/game path from launcher cmdline.")
        return

    launcher_ids = {s.build_id for s in launcher_snaps}
    game_pids = _candidate_game_pids(hints, exclude={launcher_pid})
    overlay_pids = _overlay_pids_excluding(exclude={launcher_pid})

    if not game_pids and not overlay_pids:
        print("    No matching game process in /proc (game not running yet?).")
        return

    any_overlay = False
    all_game_snaps: list[OverlaySnap] = []

    def report_pid(gpid: int, label: str) -> None:
        nonlocal any_overlay, all_game_snaps
        gs = _snapshots_for_pid(gpid)
        gcomm = _proc_comm(gpid)
        if not gs:
            print(f"    {label} pid {gpid} ({gcomm}): no gameoverlayrenderer.so in maps")
            return
        any_overlay = True
        all_game_snaps.extend(gs)
        for g in gs:
            same = g.build_id in launcher_ids
            rel = "SAME build as launcher" if same else "DIFFERENT from launcher"
            launch_paths = {s.pathname for s in launcher_snaps}
            path_note = ""
            if g.pathname not in launch_paths:
                path_note = " (different path)" if not same else " (same build, different path)"
            print(f"    {label} pid {gpid} ({gcomm}): Build ID {g.build_id}{path_note} — {rel}")
            if launcher_snaps and g.deploy and g.deploy != launcher_snaps[0].deploy:
                print(f"      deploy: {g.deploy} vs launcher {launcher_snaps[0].deploy}")

    for gpid in game_pids:
        report_pid(gpid, "game")

    extra = [p for p in overlay_pids if p not in game_pids]
    shown_extra: list[int] = []
    if extra:
        for gpid in extra:
            try:
                if _proc_comm(gpid) in SKIP_COMMS:
                    continue
            except OSError:
                continue
            shown_extra.append(gpid)
        if shown_extra:
            print("    Also mapping overlay (any role):")
            for gpid in shown_extra:
                report_pid(gpid, "overlay")

    game_snaps = [g for gpid in game_pids for g in _snapshots_for_pid(gpid)]

    if game_pids and not game_snaps:
        if 'LD_PRELOAD=""' in launcher_cmd or "LD_PRELOAD=''" in launcher_cmd:
            print(
                '    Note: launcher cmdline clears LD_PRELOAD (""); overlay on this '
                "sh/reaper shell does not imply the game inherited preload."
            )
        if app_id == "570" or "dota" in launcher_cmd.lower():
            print(
                "    Note: Dota on linuxsteamrt64 normally maps steamrt64/gameoverlayrenderer.so "
                "in the game process when injected; ubuntu12_64 on the launcher alone matches "
                "the missing-frame-tick case in CLARITY.md."
            )
        print(
            "    → Game PIDs are running but none map gameoverlayrenderer.so; "
            "the launcher preload above does not apply to the game process."
        )
        if all_game_snaps and shown_extra:
            print(
                "    (Other non-launcher PIDs still map overlay — see “Also mapping overlay” above.)"
            )
        return

    if game_snaps and all(g.build_id in launcher_ids for g in game_snaps):
        print("    → Confirmed: game process uses the same overlay build as this launcher.")
    elif game_snaps:
        print("    → Game uses a different overlay build than this launcher shell.")


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
                if _process_role(comm, cmd) == "launcher":
                    continue
            hits.append(pid)
        except (OSError, PermissionError, FileNotFoundError):
            continue
    return hits


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
        role = _process_role(comm, cmd)
        for ent in mappings:
            try:
                info = analyze_loaded(ent)
            except (OSError, ValueError):
                continue
            rows.append(ScanRow(pid=pid, comm=comm, role=role, cmd=cmd, ent=ent, info=info))
    return rows


def _print_scan_launch_summary(rows: list[ScanRow]) -> None:
    games = [r for r in rows if r.role == "game"]
    launchers = [r for r in rows if r.role == "launcher"]
    if not games and not launchers:
        return
    print("=== Launch vs game ===")
    if games:
        by_sha: dict[str, list[ScanRow]] = defaultdict(list)
        for g in games:
            by_sha[g.info.sha256].append(g)
        for sha, grp in by_sha.items():
            r0 = grp[0]
            names = ", ".join(f"{r.comm}/{r.pid}" for r in sorted(grp, key=lambda x: x.pid))
            print(
                f"  Game ({names}): Build ID {r0.info.gnu_build_id} · deploy {r0.info.deploy_path}"
            )
    for lr in sorted(launchers, key=lambda x: x.pid):
        game_sha = games[0].info.sha256 if games else None
        if game_sha and lr.info.sha256 == game_sha:
            print(f"  Launcher {lr.comm}/{lr.pid}: same overlay build as game")
        elif games:
            print(
                f"  Launcher {lr.comm}/{lr.pid}: Build ID {lr.info.gnu_build_id} · "
                f"{lr.info.deploy_path} — differs from game (often unused 32-bit preload on reaper)"
            )
        else:
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
            _print_launcher_game_check(lr.pid, lr.cmd, snaps)
    print()


def print_scan_deduped(
    pids: list[int],
    *,
    brief: bool,
    live: bool,
    shm_sample_sec: float,
    no_shm: bool,
) -> bool:
    rows = _gather_scan_rows(pids)
    if not rows:
        return False
    by_sha: dict[str, list[ScanRow]] = defaultdict(list)
    for row in rows:
        by_sha[row.info.sha256].append(row)

    n_proc = len({r.pid for r in rows})
    print(
        f"=== {len(by_sha)} distinct overlay build(s) · "
        f"{n_proc} process(es) mapping gameoverlayrenderer.so ===\n"
    )
    for idx, sha in enumerate(sorted(by_sha.keys()), 1):
        group = sorted(by_sha[sha], key=lambda r: (r.info.deploy_path or "", r.pid))
        sample = group[0]
        dep = sample.info.deploy_path or "?"
        print(f"--- build {idx}/{len(by_sha)} · {dep} · Build ID {sample.info.gnu_build_id} ---")
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
                _print_layer_vulkan_status(r.pid, indent="      ", brief=brief)
                if not no_shm:
                    print_inputevent_shm(
                        r.pid, indent="      ", brief=brief, sample_seconds=shm_sample_sec
                    )
        print()

    if not brief:
        _print_scan_launch_summary(rows)
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
    role = _process_role(comm, cmd)

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
        print("Showing game-role PIDs only (launcher preloads hidden).\n")


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
        help="All processes that currently map gameoverlayrenderer.so",
    )
    ap.add_argument(
        "--games-only",
        action="store_true",
        help="With --scan, hide launcher shells (sh/reaper); default lists every PID",
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
        default=1.0,
        metavar="SEC",
        help="Seconds between InputEvent SHM cursor reads (default 1)",
    )
    ap.add_argument(
        "--no-shm",
        action="store_true",
        help="Skip GameOverlay_InputEventStream_* sampling",
    )
    args = ap.parse_args(argv)

    if args.scan:
        games_only = args.games_only and not args.include_launchers
        print_scan_preamble(games_only=games_only)
        pids = pids_with_overlay_loaded(include_launchers=not games_only)
        if not pids:
            print("No process maps gameoverlayrenderer.so.", file=sys.stderr)
            return 1
        ok = print_scan_deduped(
            pids,
            brief=args.brief,
            live=not args.no_live,
            shm_sample_sec=args.shm_sample_sec,
            no_shm=args.no_shm,
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
