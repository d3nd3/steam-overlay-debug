#!/usr/bin/env python3
"""Official online cross-checks: SteamTracking client manifest CRC, Valve debuginfod."""

from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

UA = "steam-overlay-debug/0.1 (+https://github.com/d3nd3/steam-overlay-debug; #11446)"
STEAMTRACKING_MANIFEST = (
    "https://raw.githubusercontent.com/SteamDatabase/SteamTracking/master/"
    "ClientExtracted/ClientContentLinux.txt"
)
STEAMTRACKING_CLIENT_MANIFEST = (
    "https://raw.githubusercontent.com/SteamDatabase/SteamTracking/master/"
    "ClientManifest/steam_client_ubuntu12"
)
DEBUGINFOD = "https://debuginfod.steamos.cloud/buildid/{build_id}/debuginfo"
_manifest_text: str | None = None
_tracking_client_build: str | None = None


@dataclass
class OnlineHit:
    source: str
    url: str
    detail: str | None = None


@dataclass
class OnlineReport:
    sha256: str
    gnu_build_id: str | None = None
    hits: list[OnlineHit] = field(default_factory=list)

    def lines(self) -> list[str]:
        out = ["  Online lookup:"]
        if not self.hits:
            out.append("    (skipped or unavailable — use without --no-live)")
            return out
        for h in self.hits:
            extra = f" — {h.detail}" if h.detail else ""
            out.append(f"    [{h.source}]{extra}")
            out.append(f"      {h.url}")
        return out


def steam_client_build_date(build: str) -> str:
    try:
        return datetime.fromtimestamp(int(build), tz=timezone.utc).strftime("%Y-%m-%d")
    except (OSError, ValueError, OverflowError):
        return "?"


def _get(url: str, timeout: float = 20.0) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
        return None


def _manifest() -> str | None:
    global _manifest_text
    if _manifest_text is None:
        _manifest_text = _get(STEAMTRACKING_MANIFEST) or ""
    return _manifest_text or None


def _tracking_snapshot_build() -> tuple[str | None, str | None]:
    global _tracking_client_build
    if _tracking_client_build is None:
        text = _get(STEAMTRACKING_CLIENT_MANIFEST)
        if text:
            m = re.search(r'"version"\s+"(\d+)"', text)
            _tracking_client_build = m.group(1) if m else ""
        else:
            _tracking_client_build = ""
    if not _tracking_client_build:
        return None, None
    return _tracking_client_build, steam_client_build_date(_tracking_client_build)


def _overlay_path_crc_index(text: str) -> dict[str, str]:
    idx: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        path = parts[1].replace("\\", "/")
        if "gameoverlayrenderer" in path.lower() or "steamoverlayvulkanlayer" in path.lower():
            idx[path] = parts[0].lower()
    return idx


def _local_steam_client_build(overlay_path: str | None) -> tuple[str | None, str | None]:
    if not overlay_path:
        return None, None
    p = Path(overlay_path)
    root: Path | None = None
    for parent in p.parents:
        if (parent / "package").is_dir() and (parent / "ubuntu12_64").is_dir():
            root = parent
            break
    if not root:
        return None, None
    manifest = root / "package" / "steam_client_ubuntu12.manifest"
    if not manifest.is_file():
        return None, None
    m = re.search(r'"version"\s+"(\d+)"', manifest.read_text())
    if not m:
        return None, None
    ver = m.group(1)
    return ver, steam_client_build_date(ver)


def steamtracking_crc(
    data: bytes,
    *,
    manifest_relpath: str | None = None,
    overlay_path: str | None = None,
) -> OnlineHit | None:
    crc = f"{zlib.crc32(data) & 0xffffffff:08x}"
    text = _manifest()
    if text is None:
        return None
    snap_ver, snap_date = _tracking_snapshot_build()
    local_ver, local_date = _local_steam_client_build(overlay_path)
    snap_label = (
        f"SteamTracking snapshot client build {snap_ver} (~{snap_date})"
        if snap_ver
        else "SteamTracking snapshot"
    )
    local_label = (
        f"installed client build {local_ver} (~{local_date})"
        if local_ver
        else None
    )

    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == crc:
            return OnlineHit(
                "SteamTracking ClientContentLinux",
                STEAMTRACKING_MANIFEST,
                detail=f"CRC {crc} → {parts[1]} (matches {snap_label})",
            )

    path_index = _overlay_path_crc_index(text)
    rel = (manifest_relpath or "").replace("\\", "/").lstrip("/")
    tracked_path = None
    tracked_crc = None
    if rel:
        for path, tcrc in path_index.items():
            if path == rel or path.endswith("/" + rel):
                tracked_path, tracked_crc = path, tcrc
                break

    if tracked_path and tracked_crc and tracked_crc != crc:
        detail = (
            f"newer than {snap_label}: {tracked_path} was CRC {tracked_crc}, "
            f"local CRC {crc}"
        )
        if local_label:
            detail += f"; {local_label}"
        return OnlineHit("SteamTracking ClientContentLinux", STEAMTRACKING_MANIFEST, detail=detail)

    detail = f"CRC {crc} not in {snap_label}"
    if local_label:
        detail += f"; {local_label} (minimum: newer than tracked snapshot"
        if snap_ver:
            detail += f" {snap_ver} ~{snap_date}"
        detail += ")"
    else:
        detail += " (local file newer than SteamDB tracking baseline)"
    return OnlineHit("SteamTracking ClientContentLinux", STEAMTRACKING_MANIFEST, detail=detail)


def debuginfod_build_id(build_id: str) -> OnlineHit | None:
    url = DEBUGINFOD.format(build_id=build_id.lower())
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                return OnlineHit("debuginfod.steamos.cloud", url, detail="debuginfo available")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return OnlineHit(
                "debuginfod.steamos.cloud",
                url,
                detail="404 (client overlay not published; SLR/SteamOS packages only)",
            )
    except (urllib.error.URLError, TimeoutError):
        return None
    return None


def lookup_binary(
    data: bytes,
    *,
    gnu_build_id: str | None = None,
    manifest_relpath: str | None = None,
    overlay_path: str | None = None,
    live: bool = True,
) -> OnlineReport:
    rep = OnlineReport(sha256=hashlib.sha256(data).hexdigest(), gnu_build_id=gnu_build_id)
    if not live:
        return rep
    st = steamtracking_crc(
        data, manifest_relpath=manifest_relpath, overlay_path=overlay_path
    )
    if st:
        rep.hits.append(st)
    if gnu_build_id:
        di = debuginfod_build_id(gnu_build_id)
        if di:
            rep.hits.append(di)
    return rep
