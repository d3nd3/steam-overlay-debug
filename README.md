# steam-overlay-debug

Linux tooling for [ValveSoftware/steam-for-linux#11446](https://github.com/ValveSoftware/steam-for-linux/issues/11446) — overlay **`gameoverlayrenderer.so`** loaded but InputEvent shared memory fills when the per-frame clear path does not run.

## Install

```bash
git clone https://github.com/d3nd3/steam-overlay-debug.git
cd steam-overlay-debug
pipx install .   # or: pip install -e .
```

## Quick use

```bash
overlay-scan --scan
overlay-scan --comm dota2
overlay-scan --scan --no-live -q
overlay-scan --comm dota2 --shm-sample-sec 2
```

## What `--scan` reports

| Check | Healthy hint | Broken (#11446) hint |
|--------|----------------|---------------------|
| **`steamoverlayvulkanlayer.so` in maps** | Present (Vulkan titles) | Missing while renderer preloaded |
| **`ENABLE_VK_LAYER_VALVE_steam_overlay_1`** | Often set even with `SteamNoOverlayUI=1` | Absent when layer missing |
| **InputEvent SHM write cursor @ byte +4** | ~**8 B/s** idle creep (frame heartbeat) | **Flat** on idle; rises toward **524288** with input only |
| **Overlay build ID** | Game vs launcher / `steamrt64` vs `ubuntu12_64` | Stale or wrong tree |

### InputEvent SHM

- Path: **`/dev/shm/GameOverlay_InputEventStream_{pid}`**
- Map size **524304** = **524288** byte ring + **16** byte header; some builds map **524288** (`0x80000`) total
- The tool reads the **uint32 at offset +4**, waits **`--shm-sample-sec`** (default **1**), reads again, prints **Δ B/s**

Offline binary inspection:

```bash
overlay-version ~/.steam/debian-installation/ubuntu12_64/gameoverlayrenderer.so
```
