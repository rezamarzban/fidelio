# Security notes - Fidelio dbb05f0, patches 0001-0014

This document describes the security hardening applied in the `atecc-support` branch
(base commit `dbb05f06ca8ce606b5de5a1889ef859488ea851d` + patches 0001–0014).

**Verification status:** checked on a host-side test rig and against Microchip’s
CryptoAuthLib sources. **Not tested on real silicon.**

## What these patches defend against

| # | Weakness in dbb05f0 | Fix |
|---|---|---|
| 0001 | Uninitialised stack bytes sent over USB (INIT / VERSION / error frames) | Frames zeroed; proper CTAPHID error frames |
| 0002 | U2F sign-without-presence (p1=0x08); unbounded button wait; handle not checked before button; held button auto-approves; secrets left on error paths | Removed / bounded 30 s / checked first / fresh press required / single scrubbing exit |
| 0003 | Stray continuation frame replays a finished request | Message retired after execution |
| 0004 | authenticatorReset without button; CBOR 32-bit length wrap-around → out-of-bounds read (reproduced with ASan); unbounded CBOR recursion; unvalidated ECDH point; PIN retry spent after comparison; no minimum PIN length; non-constant-time compares | All fixed |
| 0005 | RNG seeded only from floating-pin ADC LSBs; master key could be provisioned from a failed RNG | ROSC jitter + timer mixed through SHA-256; keygen refuses on RNG failure |
| 0006 | `flash_range_program` called with non-page sizes (reads past the structure) | Whole 0xFF-padded pages |
| 0007 | Dead resident-key store / FDO code (attack surface) | Removed; `rk=true` rejected (0x2B) |
| 0008 | CTAPHID: other channels could inject continuation frames; INIT wiped an in-flight message; no channel allocation; reply continuation frames had CID 0; no timeout; no PING/WINK | CID checks, CHANNEL_BUSY, real channels, timeout, PING/WINK/CANCEL |
| 0009 | setPIN on a fresh key needed no physical presence; wrong error codes | Button required; PIN_REQUIRED / PIN_AUTH_INVALID |
| 0010 | Repeated/biased ECDSA nonces leak keys when the RNG is weak | RFC 6979 deterministic nonces (plus release of wolfSSL’s per-signature nonce buffer that otherwise leaked heap on every signature – found with ASan) |
| 0011 | Build not forced to RAM layout; image could grow into key/counter sectors | `copy_to_ram` forced; build fails if image ≥ 0x70000 |
| 0012 | Reset cleared the PIN but kept the master key: a thief could reset (clearing the PIN retry lock) and keep using every credential | Reset rotates the master key (CTAP2: reset invalidates all credentials) |
| 0013 | (optional) Root secret readable from flash | Secure-element mode (ATECC608 on I2C, selected by a GP6–GP7 jumper at power-up): the root secret stays in the chip and all key derivation is computed by it; fail-closed (never falls back to software); chip serial bound at enrolment; enrolment destroys the software master key; U2F counter never goes backwards. See `SE.md` |
| 0014 | No pinned reference for the driver that was cross-checked against Microchip sources | CryptoAuthLib added as a git submodule (pinned to v3.8.0 / `d49c7d5`). **Not linked into the firmware** – present only as reference and for provisioning tools. See licence note in `SE.md`. |

## Behaviour changes you will notice

* CTAP2 reset (also the way out of a PIN lock-out) now **INVALIDATES every U2F registration and CTAP2 credential** – you must re-enrol afterwards.
* **First boot in SE mode permanently destroys the software master key** (and with it every software-mode registration). Read `SE.md` before fitting the jumper.
* Reset only works within 10 s of plugging in, with a button tap.
* setPIN needs a tap.
* U2F “sign without presence” is gone.
* `rk=true` (passkeys / discoverable credentials) is refused – this firmware has no resident-key store.

## What no software patch can fix (read this)

* **Physical access.** The RP2040 has no encrypted flash and no secure boot in this firmware. The master key (in software mode), the attestation private key (compiled into `src/cert.c`) and the PIN hash are readable by anyone who can dump the flash (SWD / BOOTSEL). Treat a stolen device as having all its credentials extractable. Only a hardware secure element changes the root-secret part of that statement.
* **Entropy quality** (0005) depends on the board and could not be measured. Deterministic nonces (0010) limit the damage of a weak RNG for signatures, but the master key and credential nonces still come from the RNG.
* **U2F attestation is per-device** (inherent to U2F): sites can link your registrations.
* **Side channels** (power / EM / silicon timing) were not assessed. wolfSSL SP math with `ECC_TIMING_RESISTANT` is enabled.
* **No claim of being unbreakable.** This is a best-effort hardening of a small firmware with no independent audit, not yet run on real hardware. Flash a spare board first and test with your real services.

## Optional Secure Element (patch 0013)

See `SE.md` for the full description:

- What runs in the ATECC608 vs what still runs on the RP2040
- Fail-closed behaviour and LED error codes
- Wiring and jumper requirements
- Limits (unencrypted I2C bus, no rate-limit in the chip, PIN hash and attestation key still in flash)
- Provisioning requirements (config + data zones locked, HMAC secret in the chosen slot)
- Explicit statement that the driver has been cross-checked against CryptoAuthLib (`lib/hal` + `lib/calib`) but **has never been tested against a real chip**

## CryptoAuthLib submodule (patch 0014)

`lib/cryptoauthlib` is Microchip’s library pinned to commit `d49c7d578efb09d4a498d5ab86839d4c17812f15` (v3.8.0).

It is **not compiled into the firmware**. `CMakeLists.txt` lists sources explicitly and does not touch this directory, so the binary size and licence surface are unchanged.

It is present as:

1. The exact reference the `src/se.c` driver was checked against.
2. A convenient source of Microchip’s official provisioning tools (`python/`, `app/`).

**Licence note:** Microchip’s licence allows use “exclusively with Microchip products” and requires its terms to be redistributed. Fidelio is GPL. Keeping the library as a separate submodule is fine; **linking its code into a firmware image you distribute would combine the two licences**, which do not obviously fit. For personal builds this does not arise. Ask a lawyer before shipping binaries that contain CryptoAuthLib code.
