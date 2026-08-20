# Motoko firmware — one repo, all boards → scriptkitty (gated until verified)

**Motoko** is an 802.11 "radio pipe" for Retia hardware: it captures Wi-Fi frames and
streams them to a host over a SLIP protocol, and transmits arbitrary frames **only when a
host program drives it**. It ships **inert** — no attack tooling lives on the device.
The host-side tools (scan/sniff/visualize, and the authorized research console) live in the
Motoko project (https://motoko.site); this repo is **firmware only**.

This is the single build source for the Motoko firmware family, following the Retia
release-channel methodology (same as `RetiaLLC/WLEDkitty`, `RetiaLLC/CircuitPython`):

```
    firmware source (this repo, all boards)
        │  push a release  (motoko-release.yml  → PRERELEASE = untested auto-build)
        ▼
    GitHub release  motoko-v<ver>-sk.<n>   with one asset per board
        │  hardware-verify → motoko-promote.yml attaches verification-<device>.json,
        │                    flips prerelease → full release (= VERIFIED)
        ▼
    scriptkitty.sh  channel cards (one per board) pull automatically:
        • full release + verification-<device>.json → the flasher's DEFAULT (verified ✓)
        • prerelease → shown under "⚠ untested auto-builds", never the default
```

## Supported boards

See [`boards.yaml`](../boards.yaml). Today:

| device | MCU | build | release asset | scriptkitty card |
|---|---|---|---|---|
| **newsheen** (Newsheen/Pusheen puck) | ESP32-S3 | PlatformIO (CI) | `motoko-newsheen.factory.bin` | `newsheen-motoko` |
| **wifi-nugget** | ESP8266 | prebuilt (patched SDK) | `motoko-wifi-nugget.bin` | `wifi-nugget-motoko-bpi` |

The ESP32-S3 build is compiled fresh in CI. The ESP8266 bin is built against a **patched
esp8266 SDK** so `wifi_send_pkt_freedom()` radiates deauth (stock cores return −1 and radiate
nothing) — that toolchain isn't reproducible in stock CI yet, so the WiFi Nugget ships its
verified prebuilt bin (source is here for transparency). Reproducing it in CI is the one open
item to make *every* board fully CI-built.

## Capability note (the ESP32-S3 vs ESP8266 delta)

The ESP8266 promiscuous callback hard-caps frames at ~112 bytes (SDK/ROM limit), so RSN/WPS
and EAPOL key-data get truncated. The ESP32-S3 (`firmware/newsheen`) captures **full frames**
→ complete recon, whole WPA handshakes, and PMKIDs; it also does raw/deauth TX on the **stock**
SDK (via the `ieee80211_raw_frame_sanity_check()` override) and can present a WebHID interface.
All boards speak the **same SLIP wire protocol**, so the same host display works across them.

## Build locally

```bash
# ESP32-S3 Newsheen (PlatformIO)
cd firmware/newsheen
pio run -e newsheen-motoko                       # -> .pio/build/newsheen-motoko/firmware.bin
# host protocol tests (no hardware needed)
cd host && cc -O2 -o fw_logic_test fw_logic_test.c && ./fw_logic_test && node display_test.cjs
```

## Cut & promote a release

```bash
# 1. Auto build -> UNTESTED prerelease (all boards)
gh workflow run motoko-release.yml --repo RetiaLLC/motoko-firmware -f notes="what changed"

# 2. After flashing + confirming on real hardware (operator-approved):
gh workflow run motoko-promote.yml --repo RetiaLLC/motoko-firmware \
  -f tag=motoko-v4.0.0-sk.1 -f device=newsheen -f method=human -f notes="boot + on-air capture OK"
#   device: newsheen | wifi-nugget | all ;  method: human | workbench
```

Never promote a build nobody flashed — promotion is the quality gate.

## Provenance

- ESP32-S3 source: this repo, `firmware/newsheen` (ported from `skickar/motoko-bpi`).
- ESP8266 source: this repo, `firmware/wifi-nugget/bridge` (Motoko v3, `skickar/motoko-bpi`).
- The Vanhoef/attack toolkit is **NOT** here — it stays in private `skickar/motoko-bpi`.
- Labeling stays honest per the `dual-use-safe-publish` methodology: neutral radio pipe,
  ships inert, host-driven TX incl. deauth, authorized-RF-only.
