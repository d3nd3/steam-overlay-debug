#!/usr/bin/env python3
"""Identify Valve gameoverlayrenderer builds (Windows PE / Linux ELF)."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

OVERLAY_NAME = re.compile(r"gameoverlayrenderer|steamoverlayvulkanlayer", re.I)
UTF16_FILE_VERSION = re.compile(
    rb"(?:[\x30-\x39]\x00){1,2}(?:\.\x00(?:[\x30-\x39]\x00){1,2}){3}"
)
ASCII_FILE_VERSION = re.compile(rb"(?<![\d.])(?:\d{1,2}\.){3}\d{1,2}(?![\d.])")
PRODUCT_VERSION = "01.00.00.01"
BUILD_BRANCH = re.compile(rb"steam_rel_client(?:_hotfix)?_win64")
OVERLAY_SUFFIX = {".so", ".dll", ".exe"}
IDA_SIDECAR_EXTS = (".i64", ".id0", ".id1", ".id2", ".nam", ".til")


@dataclass(frozen=True)
class OverlayVersion:
    path: Path
    platform: str
    version: str
    version_label: str
    file_version: str | None
    numeric_id: str | None
    build_branch: str | None
    gnu_build_id: str | None
    toolchain: str | None
    fingerprint: str | None
    debug_link: str | None
    sha256: str
    deploy_path: str | None = None

    def lines(self) -> list[str]:
        out = [f"{self.path}", f"  Version: {self.version}"]
        if self.fingerprint:
            out.append(f"  fingerprint: {self.fingerprint}")
        if self.debug_link:
            out.append(f"  debug_link: {self.debug_link}")
        out.append(f"  platform: {self.platform}")
        if self.deploy_path:
            out.append(f"  deploy_path: {self.deploy_path}")
        if self.file_version:
            out.append(f"  FileVersion: {self.file_version}")
        if self.numeric_id:
            out.append(f"  numeric_id: {self.numeric_id}")
        if self.build_branch:
            out.append(f"  build_branch: {self.build_branch}")
        if self.gnu_build_id:
            out.append(f"  GNU Build ID: {self.gnu_build_id}")
        out.append(f"  version_label: {self.version_label}")
        out.append(f"  sha256: {self.sha256}")
        return out

    def with_online(self, live: bool = True) -> list[str]:
        from online_lookup import lookup_binary

        data = self.path.read_bytes()
        rep = lookup_binary(
            data,
            gnu_build_id=self.gnu_build_id,
            manifest_relpath=(
                f"{self.deploy_path}/gameoverlayrenderer.so" if self.deploy_path else None
            ),
            overlay_path=str(self.path),
            live=live,
        )
        return self.lines() + rep.lines()

    def proc_summary(self, *, vma: str = "", perms: str = "") -> list[str]:
        lines = [f"  Build ID:  {self.gnu_build_id or self.sha256}"]
        if self.file_version:
            lines.append(f"  FileVersion: {self.file_version} ({self.numeric_id})")
        if self.fingerprint:
            lines.append(f"  Fingerprint: {self.fingerprint}")
        if self.deploy_path:
            lines.append(f"  Deploy slot: {self.deploy_path}")
        lines.append(f"  Sort key:  {self.version_label}")
        lines.append(f"  SHA-256:   {self.sha256}")
        if vma:
            lines.append(f"  Map:       {vma} {perms}".rstrip())
        return lines


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _numeric_id(file_version: str) -> str:
    return "".join(file_version.split("."))


def _pe_versions(data: bytes) -> list[str]:
    return [m.group().decode("utf-16-le") for m in UTF16_FILE_VERSION.finditer(data)]


def _pick_file_version(candidates: list[str]) -> str | None:
    usable = [v for v in candidates if v != PRODUCT_VERSION]
    if not usable:
        return None
    return max(usable, key=lambda v: tuple(int(p) for p in v.split(".")))


def _ascii_file_versions(data: bytes) -> list[str]:
    out: list[str] = []
    for m in ASCII_FILE_VERSION.finditer(data):
        s = m.group().decode("ascii", "replace")
        if s == PRODUCT_VERSION or s.startswith("150."):
            continue
        parts = s.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts) and int(parts[0]) >= 8:
            out.append(s)
    return out


def _embedded_file_version(data: bytes) -> str | None:
    v = _pick_file_version(_pe_versions(data))
    return v or _pick_file_version(_ascii_file_versions(data))


def _toolchain_tag(toolchain: str | None) -> str | None:
    if not toolchain:
        return None
    mold = re.search(r"mold\s+[\d.]+", toolchain)
    rt = re.search(r"SteamRT\s+[\d.~+\w-]+", toolchain)
    bits = [m.group(0) for m in (rt, mold) if m]
    return ", ".join(bits) if bits else toolchain[:60]


def _deploy_path_from_hint(hint_path: str) -> str | None:
    s = hint_path.replace("\\", "/")
    base = s.rsplit("/", 1)[-1]
    for v in ("steamrt64", "steamrt32", "ubuntu12_64", "ubuntu12_32"):
        if f"/{v}/" in s or base.startswith(f"{v}_"):
            return v
    if "pressure-vessel-libs" in s:
        return "pressure-vessel-libs"
    return None


def _elf_version_label(bid: str | None, deploy: str | None, hint: str) -> str:
    if not bid:
        return "linux_unknown"
    short = bid[:8]
    layer = "_layer" if "vulkanlayer" in hint.lower() else ""
    if deploy:
        return f"{deploy}{layer}_{short}"
    return f"linux_{short}"


def _compose_version(
    *, file_version: str | None, numeric_id: str | None, gnu_build_id: str | None, sha256: str
) -> str:
    if file_version and numeric_id:
        return f"{file_version} ({numeric_id})"
    if gnu_build_id:
        return gnu_build_id
    return sha256


def _pe_branch(data: bytes) -> str | None:
    m = BUILD_BRANCH.search(data)
    return m.group(0).decode("ascii") if m else None


def _elf_shmeta(data: bytes) -> tuple[int, int, int, int, str] | None:
    if data[:4] != b"\x7fELF" or data[5] != 1:
        return None
    le, ei_class = "<", data[4]
    if ei_class == 2:
        e_shoff = struct.unpack_from(le + "Q", data, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(le + "HHH", data, 0x3A)
        sh_fmt, sh_size_off, sh_link_off = le + "IIQQQQIIQQ", 48, 40
    elif ei_class == 1:
        e_shoff = struct.unpack_from(le + "I", data, 0x20)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(le + "HHH", data, 0x2E)
        sh_fmt, sh_size_off, sh_link_off = le + "IIIIIIIIII", 20, 24
    else:
        return None
    if e_shnum == 0 and e_shoff:
        e_shnum = struct.unpack_from(le + ("Q" if ei_class == 2 else "I"), data, e_shoff + sh_size_off)[0]
    if e_shstrndx == 0xFFFF and e_shoff:
        e_shstrndx = struct.unpack_from(le + "I", data, e_shoff + sh_link_off)[0]
    return e_shoff, e_shentsize, e_shnum, e_shstrndx, sh_fmt


def _elf_section_raw(data: bytes, section: str) -> bytes | None:
    meta = _elf_shmeta(data)
    if not meta:
        return None
    e_shoff, e_shentsize, e_shnum, e_shstrndx, sh_fmt = meta
    le = "<"

    def sh_entry(i: int):
        return struct.unpack_from(sh_fmt, data, e_shoff + i * e_shentsize)

    shstr_off = sh_entry(e_shstrndx)[4]
    for i in range(e_shnum):
        name_idx = struct.unpack_from(le + "I", data, e_shoff + i * e_shentsize)[0]
        start = shstr_off + name_idx
        end = data.index(b"\x00", start)
        if data[start:end].decode("ascii", "replace") != section:
            continue
        sec = sh_entry(i)
        return data[sec[4] : sec[4] + sec[5]]
    return None


def _elf_note_build_id(data: bytes) -> str | None:
    raw = _elf_section_raw(data, ".note.gnu.build-id")
    if not raw or len(raw) < 12:
        return None
    namesz, descsz, _ = struct.unpack_from("<III", raw, 0)
    name_end = 12 + ((namesz + 3) // 4) * 4
    desc = raw[name_end : name_end + descsz]
    return desc.hex() if desc else None


def _elf_comment_lines(data: bytes) -> list[str]:
    raw = _elf_section_raw(data, ".comment")
    if not raw:
        return []
    return [p.decode("utf-8", "replace").strip() for p in raw.split(b"\x00") if p.strip()]


def _steamrt_gcc_comment(comments: list[str]) -> str | None:
    rt_lines = [c for c in comments if "SteamRT" in c and "GCC" in c]
    if not rt_lines:
        return None
    return max(rt_lines, key=lambda c: tuple(int(x) for x in re.findall(r"\d+", c)[:4] or [0]))


def _elf_fingerprint(data: bytes) -> str | None:
    comments = _elf_comment_lines(data)
    if not comments:
        return None
    mold = next((c for c in comments if c.startswith("mold ")), None)
    rt = _steamrt_gcc_comment(comments)
    bits = []
    if rt:
        bits.append(_toolchain_tag(rt) or rt)
    if mold:
        bits.append(_toolchain_tag(mold) or mold)
    return "; ".join(bits) if bits else None


def _elf_debug_link(data: bytes) -> str | None:
    raw = _elf_section_raw(data, ".gnu_debuglink")
    if not raw:
        return None
    end = raw.find(b"\x00")
    return raw[:end].decode("ascii", "replace") if end > 0 else None


def is_overlay_renderer(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in OVERLAY_SUFFIX
        and OVERLAY_NAME.search(path.name) is not None
    )


def analyze_bytes(
    data: bytes, source: Path | str = "<bytes>", *, hint_path: str = ""
) -> OverlayVersion:
    path = Path(source)
    hint = hint_path or str(source)
    sha = _sha256_bytes(data)
    deploy = _deploy_path_from_hint(hint)
    fv = _embedded_file_version(data)
    num = _numeric_id(fv) if fv else None
    if data[:2] == b"MZ":
        label = f"{fv}_{num}" if fv and num else (fv or sha[:16])
        return OverlayVersion(
            path=path,
            platform="pe",
            version=_compose_version(file_version=fv, numeric_id=num, gnu_build_id=None, sha256=sha),
            version_label=label,
            file_version=fv,
            numeric_id=num,
            build_branch=_pe_branch(data),
            gnu_build_id=None,
            toolchain=None,
            fingerprint=None,
            debug_link=None,
            sha256=sha,
            deploy_path=deploy,
        )
    if data[:4] == b"\x7fELF":
        bid = _elf_note_build_id(data)
        fp = _elf_fingerprint(data)
        label = _elf_version_label(bid, deploy, hint)
        return OverlayVersion(
            path=path,
            platform="elf",
            version=_compose_version(file_version=fv, numeric_id=num, gnu_build_id=bid, sha256=sha),
            version_label=label,
            file_version=fv,
            numeric_id=num,
            build_branch=None,
            gnu_build_id=bid,
            toolchain=fp,
            fingerprint=fp,
            debug_link=_elf_debug_link(data),
            sha256=sha,
            deploy_path=deploy,
        )
    raise ValueError(f"not a PE or ELF overlay binary: {source}")


def analyze(path: Path) -> OverlayVersion:
    return analyze_bytes(path.read_bytes(), path.resolve())


def collect_paths(inputs: list[Path], recursive: bool) -> list[Path]:
    found: list[Path] = []
    for root in inputs:
        root = root.resolve()
        if root.is_file():
            if root.suffix.lower() in OVERLAY_SUFFIX:
                found.append(root)
            continue
        if not root.is_dir():
            continue
        it = root.rglob("*") if recursive else root.iterdir()
        for p in it:
            if is_overlay_renderer(p):
                found.append(p)
    return sorted(set(found))


def sort_into_folders(paths: list[Path], dest_root: Path, mode: str, dry_run: bool) -> None:
    dest_root.mkdir(parents=True, exist_ok=True)
    for p in paths:
        info = analyze(p)
        folder = dest_root / info.version_label
        if not dry_run:
            folder.mkdir(parents=True, exist_ok=True)
        target = folder / p.name
        if target.resolve() == p.resolve():
            _move_ida_sidecars(p, folder, dry_run)
            print(f"skip (already in place): {p}")
            continue

        def hardlink(src: str, dst: str) -> None:
            d = Path(dst)
            if d.exists():
                d.unlink()
            d.hardlink_to(src)

        action = {"copy": shutil.copy2, "move": shutil.move, "link": hardlink}[mode]
        print(f"{mode}: {p} -> {target}")
        if not dry_run:
            action(str(p), str(target))
        _move_ida_sidecars(p if mode == "move" else target, folder, dry_run)
    relocate_loose_ida(dest_root, dry_run)
    _prune_empty_dirs(dest_root)


def _move_ida_sidecars(binary: Path, dest_dir: Path, dry_run: bool) -> None:
    base = binary.name
    for ext in IDA_SIDECAR_EXTS:
        side = binary.parent / f"{base}{ext}"
        if not side.is_file():
            continue
        target = dest_dir / side.name
        if side.resolve() == target.resolve():
            continue
        print(f"sidecar: {side} -> {target}")
        if not dry_run:
            shutil.move(str(side), str(target))


def relocate_loose_ida(root: Path, dry_run: bool) -> None:
    for i64 in sorted(root.rglob("*.i64")):
        stem = i64.name[:-4]
        if not stem:
            continue
        matches = [
            c
            for c in root.rglob(stem)
            if c.is_file() and c.suffix.lower() in OVERLAY_SUFFIX
        ]
        if not matches:
            continue
        binary = matches[0]
        try:
            folder = root / analyze(binary).version_label
        except ValueError:
            continue
        if not dry_run:
            folder.mkdir(parents=True, exist_ok=True)
        for parent in {i64.parent, binary.parent}:
            for ext in IDA_SIDECAR_EXTS:
                side = parent / f"{stem}{ext}"
                if not side.is_file():
                    continue
                target = folder / side.name
                if side.resolve() == target.resolve():
                    continue
                print(f"sidecar: {side} -> {target}")
                if not dry_run:
                    shutil.move(str(side), str(target))


def _prune_empty_dirs(root: Path) -> None:
    for d in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        try:
            d.rmdir()
        except OSError:
            pass


def version_md_targets(root: Path) -> list[Path]:
    root = root.resolve()
    if not root.is_dir():
        return []
    overlays = [p for p in root.iterdir() if p.is_file() and is_overlay_renderer(p)]
    if overlays:
        return [root]
    return sorted(
        d
        for d in root.iterdir()
        if d.is_dir()
        and any(p.is_file() and is_overlay_renderer(p) for p in d.iterdir())
    )


def write_version_md(folder: Path, *, live: bool = True, dry_run: bool = False) -> None:
    bins = sorted(p for p in folder.iterdir() if p.is_file() and is_overlay_renderer(p))
    if not bins:
        return
    chunks = [f"# {folder.name}\n"]
    for p in bins:
        info = analyze(p)
        body = "\n".join(info.with_online(live=live))
        chunks.append(f"\n## `{p.name}`\n\n```\n{body}\n```\n")
    out = folder / "VERSION.md"
    text = "".join(chunks)
    print(f"write: {out}")
    if not dry_run:
        out.write_text(text, encoding="utf-8")


def write_version_md_tree(root: Path, *, live: bool = True, dry_run: bool = False) -> None:
    for folder in version_md_targets(root):
        write_version_md(folder, live=live, dry_run=dry_run)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Report gameoverlayrenderer version ids.")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("-r", "--recursive", action="store_true")
    ap.add_argument("--sort", type=Path, metavar="OUT_DIR")
    ap.add_argument("--move", action="store_true")
    ap.add_argument("--link", action="store_true")
    ap.add_argument("-n", "--dry-run", action="store_true")
    ap.add_argument(
        "--online-lookup",
        action="store_true",
        help="Cross-check via SteamTracking manifest CRC + debuginfod (ELF Build ID)",
    )
    ap.add_argument(
        "--no-live",
        action="store_true",
        help="With --online-lookup, skip HTTP requests",
    )
    ap.add_argument(
        "--write-version-md",
        action="store_true",
        help="Write VERSION.md (local ids + online lookup) in each version subfolder",
    )
    args = ap.parse_args(argv)
    only_md = args.write_version_md and not args.online_lookup and not args.sort
    if only_md:
        live = not args.no_live
        for root in args.paths:
            root = root.resolve()
            if root.is_file():
                write_version_md(root.parent, live=live, dry_run=args.dry_run)
            else:
                write_version_md_tree(root, live=live, dry_run=args.dry_run)
        return 0
    paths = collect_paths(args.paths, args.recursive)
    if not paths:
        print("No gameoverlayrenderer binaries found.", file=sys.stderr)
        return 1
    for p in paths:
        try:
            info = analyze(p)
            lines = (
                info.with_online(live=not args.no_live)
                if args.online_lookup
                else info.lines()
            )
            print("\n".join(lines))
            print()
        except ValueError as e:
            print(e, file=sys.stderr)
    if args.sort:
        mode = "move" if args.move else "link" if args.link else "copy"
        sort_into_folders(paths, args.sort.resolve(), mode, args.dry_run)
    if args.write_version_md:
        live = not args.no_live
        for root in args.paths:
            root = root.resolve()
            targets = version_md_targets(root) if root.is_dir() else [root.parent]
            for folder in targets:
                write_version_md(folder, live=live, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
