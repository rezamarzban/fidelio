# Fidelio (ATECC Support)

Fidelio turns a Raspberry Pi RP2040 board into a personal USB security key supporting **FIDO2 / WebAuthn** and legacy **CTAP1 / U2F**.

This branch (`atecc-support`) contains a series of security hardening patches (0001–0014) applied on top of upstream commit `dbb05f0`.

> **Important**  
> This is **not** the same as upstream `master`. Several features and the security model have been deliberately changed. Read this document and `SECURITY.md` / `SE.md` carefully before using.

## What this version supports

- CTAP2 / FIDO2 and WebAuthn
- Legacy CTAP1 / U2F
- Physical user presence via a push-button
- FIDO2 PIN (with physical presence required for setting)
- Unlimited non-discoverable credentials
- ES256 signatures
- Optional **Secure Element** mode using Microchip ATECC608A/B/C

### What was removed / disabled

- Discoverable credentials (passkeys / resident keys) — `rk=true` is rejected
- U2F “sign without presence”
- Dead FDO / resident-key code paths

## Security model (summary)

- By default the root secret lives in flash (software mode).
- With the Secure Element jumper fitted, the root secret stays **inside the ATECC608** and never leaves the chip. All key derivation is performed by the secure element.
- CTAP2 `authenticatorReset` now **rotates the master key**, invalidating every existing credential.
- First boot with the SE jumper permanently destroys the software master key.
- The RP2040 still has no flash encryption or secure boot. A stolen device can be dumped.

See `SECURITY.md` for the full list of fixes and residual risks, and `SE.md` for Secure Element details.

## Hardware requirements

- Raspberry Pi Pico (or compatible RP2040 board)
- One normally-open push-button (presence button)
- **Optional**: Microchip ATECC608A/B/C + jumper for Secure Element mode

### Presence button (required)

| Board              | Presence button | LED          |
|--------------------|-----------------|--------------|
| Raspberry Pi Pico  | GPIO15          | On-board LED |

### Secure Element wiring (optional)

| ATECC608     | Pico pin      | Notes                              |
|--------------|---------------|------------------------------------|
| VCC / GND    | 3V3 / GND     |                                    |
| SDA / SCL    | GP4 / GP5     | 4.7 kΩ pull-ups recommended        |
| **Jumper**   | **GP6 ↔ GP7** | Must be present **at power-up**    |

Default I2C address is `0x60`. Change with `-DSE_I2C_ADDR=...` if needed.

**Warning:** The first boot with the SE jumper fitted permanently erases the software master key. All previous software-mode registrations are lost.

## Quick start

### 1. Clone and prepare

```sh
git clone --recursive https://github.com/rezamarzban/fidelio.git
cd fidelio
git checkout atecc-support
```

If you already cloned without submodules:

```sh
git submodule update --init --recursive
# CryptoAuthLib is present only as a reference (not linked into the firmware)
git submodule update --init --depth 1 lib/cryptoauthlib
```

### 2. Create your attestation certificate

```sh
./mkcert.sh
```

### 3. Build

```sh
cmake -B build -DFAMILY=rp2040 -DPICO_SDK_PATH=$PWD/pico-sdk
cmake --build build
```

The build forces a `copy_to_ram` layout and fails if the image grows into the key/counter flash region.

### 4. Flash

Hold **BOOTSEL**, plug in the Pico, then copy the UF2:

```sh
cp build/fidelio.uf2 /path/to/RPI-RP2/
```

### 5. First boot

- **Software mode** (no jumper): LED stays on while the master key is generated → press the button once.
- **SE mode** (jumper present): the device verifies the ATECC608. On any failure it blinks an error code (1–7) and never starts USB.

## Everyday use

When a site asks for the security key, connect the device and press the presence button while the LED is lit. Enter the PIN when requested.

- CTAP2 reset (or recovering from a locked PIN) **invalidates all credentials**. You must re-register afterwards.
- Reset is only accepted within ~10 seconds of plugging in and requires a button press.
- Setting a PIN always requires a physical button press.

## Secure Element mode (optional)

Enabled only when GP6 and GP7 are joined **before power-up**.

| Operation              | Software mode          | SE mode                          |
|------------------------|------------------------|----------------------------------|
| Root secret            | In flash               | Inside ATECC608 (never leaves)   |
| Key derivation         | On RP2040              | Computed by the chip             |
| Extra entropy          | ADC + ROSC + timer     | + hardware RNG from the chip     |
| Attestation key / PIN  | Still in flash         | Still in flash                   |

Supported chips: **ATECC608A / 608B / 608C** only (revision byte `0x60`).  
Other CryptoAuth devices are rejected.

The driver was cross-checked against Microchip’s CryptoAuthLib (`lib/hal` + `lib/calib`) but has **not** been tested on real silicon yet. Use a spare chip first.

Full details: see `SE.md`.

## LED error codes (Secure Element)

If the jumper is present and something is wrong, the LED blinks N times, pauses, and repeats. USB never starts.

| Flashes | Meaning                        |
|---------|--------------------------------|
| 1       | No device / communication fail |
| 2       | Not an ATECC608                |
| 3       | Config/data zones not locked   |
| 4       | Secret slot is readable        |
| 5       | Secret slot appears blank      |
| 6       | HMAC self-test failed          |
| 7       | Chip serial number mismatch    |

## Documentation

- `SECURITY.md` – what was fixed, behaviour changes, residual risks
- `SE.md` – Secure Element mode, wiring, limits, provisioning notes
- `tests/README.txt` – host-side test suite

## License

Fidelio is licensed under the **GNU General Public License v2** (or later, depending on upstream files).

CryptoAuthLib is present only as a **git submodule for reference and provisioning tools**. It is **not** compiled into the firmware. Microchip’s licence restricts use to Microchip products; linking it into a distributed binary would create a licence conflict. See the note in `SE.md`.
