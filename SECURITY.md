# Security notes - Fidelio dbb05f0, patches 0001-0013

## What these patches defend against (verified on a host rig; NOT on real hardware)
| # | Weakness in dbb05f0 | Fix |
|---|---|---|
| 0001 | Uninitialised stack bytes sent over USB (INIT / VERSION / error frames) | frames zeroed, proper CTAPHID error frames |
| 0002 | U2F sign-without-presence (p1=0x08); unbounded button wait; handle not checked before button; held button auto-approves; secrets left on error paths | removed / bounded 30 s / checked first / fresh press required / single scrubbing exit |
| 0003 | Stray continuation frame replays a finished request | message retired after execution |
| 0004 | authenticatorReset without button; CBOR 32-bit length wrap-around -> out-of-bounds read (reproduced with ASan); unbounded CBOR recursion; unvalidated ECDH point; PIN retry spent after comparison; no minimum PIN length; non-constant-time compares | all fixed |
| 0005 | RNG seeded only from floating-pin ADC LSBs; master key could be provisioned from a failed RNG | ROSC jitter + timer mixed through SHA-256; keygen refuses on RNG failure |
| 0006 | flash_range_program called with non-page sizes (reads past the structure) | whole 0xFF-padded pages |
| 0007 | dead resident-key store / FDO code (attack surface) | removed; rk=true rejected (0x2B) |
| 0008 | CTAPHID: other channels could inject continuation frames into a message; INIT wiped an in-flight message; no channel allocation; reply continuation frames had CID 0; no timeout; no PING/WINK | CID checks, CHANNEL_BUSY, real channels, timeout, PING/WINK/CANCEL |
| 0009 | setPIN on a fresh key needed no physical presence; wrong error codes | button required; PIN_REQUIRED / PIN_AUTH_INVALID |
| 0010 | repeated/biased ECDSA nonces leak keys when the RNG is weak | RFC 6979 deterministic nonces (plus release of wolfSSL's per-signature nonce buffer, which otherwise leaks heap on every signature - found with ASan) |
| 0011 | build not forced to RAM layout; image could grow into key/counter sectors | copy_to_ram forced; build fails if image >= 0x70000 |
| 0012 | reset cleared the PIN but kept the master key: a thief could reset (clearing the PIN retry lock) and keep using every credential | reset rotates the master key (CTAP2: reset invalidates all credentials) |
| 0013 | (optional) root secret readable from flash | Secure-element mode (ATECC608 on I2C, selected by a GP6-GP7 jumper at power-up): the root secret stays in the chip and all key derivation is computed by it; fail-closed (never falls back to software); chip serial bound at enrolment; enrolment destroys the software master key; U2F counter never goes backwards. See SE.md |

## Behaviour changes you will notice
* CTAP2 reset (also the way out of a PIN lock-out) now INVALIDATES every U2F registration and CTAP2 credential - re-enrol afterwards.
* **First boot in SE mode permanently destroys the software master key** (and with it every software-mode registration). Read SE.md before fitting the jumper.
* Reset only works within 10 s of plugging in, with a button tap.
* setPIN needs a tap. U2F "sign without presence" is gone. rk=true (passkeys) is refused: this firmware has no discoverable credentials.

## What no software patch can fix (read this)
* **Physical access.** The RP2040 has no encrypted flash and no secure boot here. The master key, the attestation private key (compiled into src/cert.c) and the PIN hash are readable by anyone who can dump the flash (SWD/BOOTSEL). Treat a stolen device as having all its credentials extractable. Only hardware with a secure element changes that.
* **Entropy quality** (0005) depends on the board and could not be measured. Deterministic nonces (0010) limit the damage of a weak RNG for signatures, but the master key and credential nonces still come from the RNG.
* **U2F attestation is per-device** (inherent to U2F): sites can link your registrations.
* **Side channels** (power/EM/silicon timing) were not assessed. wolfSSL SP math with ECC_TIMING_RESISTANT is enabled.
* **No claim of being unbreakable.** This is a best-effort hardening of a small firmware with no independent audit, not yet run on real hardware by me. Flash a spare board first and test with your real services.


## Optional secure element (patch 0013)
See `SE.md` (repository root of the patched tree, and also in this zip): what runs in the ATECC608, what still runs on the RP2040, the fail-closed behaviour and its limits (unencrypted I2C bus, no rate limit in the chip, PIN hash and attestation key still in flash, simulator-tested only, never run against a real chip).
