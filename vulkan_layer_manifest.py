"""Parse Vulkan implicit-layer JSON (Steam overlay) from process environment."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

STEAM_OVERLAY_LAYER = re.compile(r"steam.?overlay|VK_LAYER.*steam_overlay", re.I)
OVERLAY_VULKAN_SO = re.compile(r"steamoverlayvulkanlayer.*\.so", re.I)


@dataclass(frozen=True)
class SteamOverlayLayerManifest:
    name: str
    library_path: str
    json_path: Path
    loader_enabled: bool
    loader_disabled: bool
    library_mapped: bool


def _env_map(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k] = v
    return out


def _resolve_layer_dir(pid: int, part: str) -> Path | None:
    part = part.strip()
    if not part:
        return None
    direct = Path(part)
    if direct.is_dir():
        return direct
    proc_root = Path(f"/proc/{pid}/root")
    if not proc_root.is_dir():
        return None
    candidate = proc_root / part.lstrip("/")
    if candidate.is_dir():
        return candidate
    return None


def _layer_dirs(pid: int, env_lines: list[str]) -> list[Path]:
    dirs: list[Path] = []
    seen: set[str] = set()
    for line in env_lines:
        if line.startswith("VK_IMPLICIT_LAYER_PATH=") or line.startswith("VK_LAYER_PATH="):
            raw = line.split("=", 1)[1]
            for part in raw.split(":"):
                resolved = _resolve_layer_dir(pid, part)
                if not resolved:
                    continue
                key = str(resolved)
                if key in seen:
                    continue
                seen.add(key)
                dirs.append(resolved)
    return dirs


def _layer_enabled(env: dict[str, str], enable: dict[str, str], disable: dict[str, str]) -> tuple[bool, bool]:
    for key, want in disable.items():
        if env.get(key) == want:
            return False, True
    if not enable:
        return True, False
    for key, want in enable.items():
        if env.get(key) != want:
            return False, False
    return True, False


def _library_in_maps(pid: int, library_path: str) -> bool:
    if not library_path:
        return False
    target = Path(library_path)
    name = target.name
    maps = Path(f"/proc/{pid}/maps")
    if not maps.is_file():
        return False
    for line in maps.read_text().splitlines():
        if name in line or (target.is_absolute() and library_path in line):
            return True
    return False


def _load_layer_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    layer = data.get("layer")
    if isinstance(layer, dict):
        return layer
    return None


def steam_overlay_manifests(pid: int, env_lines: list[str]) -> list[SteamOverlayLayerManifest]:
    env = _env_map(env_lines)
    seen_json: set[Path] = set()
    out: list[SteamOverlayLayerManifest] = []
    for directory in _layer_dirs(pid, env_lines):
        if not directory.is_dir():
            continue
        for json_path in sorted(directory.glob("*.json")):
            rp = json_path.resolve()
            if rp in seen_json:
                continue
            seen_json.add(rp)
            layer = _load_layer_json(json_path)
            if not layer:
                continue
            name = str(layer.get("name") or "")
            lib = str(layer.get("library_path") or "")
            if not STEAM_OVERLAY_LAYER.search(name) and not OVERLAY_VULKAN_SO.search(lib):
                continue
            enable = layer.get("enable_environment") or {}
            disable = layer.get("disable_environment") or {}
            if not isinstance(enable, dict):
                enable = {}
            if not isinstance(disable, dict):
                disable = {}
            enabled, disabled = _layer_enabled(
                env,
                {str(k): str(v) for k, v in enable.items()},
                {str(k): str(v) for k, v in disable.items()},
            )
            out.append(
                SteamOverlayLayerManifest(
                    name=name,
                    library_path=lib,
                    json_path=json_path,
                    loader_enabled=enabled,
                    library_mapped=_library_in_maps(pid, lib),
                    loader_disabled=disabled,
                )
            )
    return out


def format_manifest_lines(
    manifests: list[SteamOverlayLayerManifest], *, indent: str, pid: int | None = None
) -> list[str]:
    if not manifests:
        hint = " (paths resolved via /proc/PID/root when using Pressure Vessel)"
        return [f"{indent}Vulkan layer manifest: (no Steam overlay JSON found{hint})"]
    proc_prefix = Path(f"/proc/{pid}/root") if pid else None
    lines: list[str] = [f"{indent}Vulkan layer manifest:"]
    for m in manifests:
        if m.loader_disabled:
            state = "disabled via disable_environment"
        elif m.loader_enabled and m.library_mapped:
            state = "enable_environment met, library mapped"
        elif m.loader_enabled:
            state = "enable_environment met, library not in maps yet"
        elif m.library_mapped:
            state = "library mapped (enable_environment not met)"
        else:
            state = "not active (enable_environment not met)"
        lines.append(f"{indent}  {m.name}: {state}")
        jp = m.json_path.name
        if proc_prefix:
            try:
                jp = str(m.json_path.relative_to(proc_prefix))
            except ValueError:
                pass
        lines.append(f"{indent}    {jp} → {m.library_path}")
    return lines
