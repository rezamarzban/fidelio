# Secure-element mode (optional)

Default: software crypto, exactly as before. Join two pins with a jumper **before power-up** and the firmware
uses a Microchip **ATECC608A/B** on I2C instead. The pins are sampled once at boot; removing the jumper later
changes nothing until the next power cycle.

## Wiring (Raspberry Pi Pico)

| ATECC608 | Pico | |
|---|---|---|
| VCC / GND | 3V3 (pin 36) / GND | |
| SDA / SCL | GP4 (pin 6) / GP5 (pin 7) | 4.7 kΩ pull-ups to 3V3 recommended |
| **jumper** | **GP6 (pin 9) to GP7 (pin 10)** | adjacent pins, one wire |

Change with `-DSE_SDA_PIN= -DSE_SCL_PIN= -DSE_JUMPER_DRIVE_PIN= -DSE_JUMPER_SENSE_PIN= -DSE_I2C_ADDR= -DSE_HMAC_SLOT=`
(`0x60` is the default address; Trust&GO parts use `0x6A`). The jumper test drives one pin both ways and requires the
other to follow, so a pin stuck high or low does not count as a jumper.

## What the chip does, what the RP2040 still does

| Operation | Software mode | SE mode |
|---|---|---|
| Root secret | 32-byte master key in flash (0x72000) | 32-byte key inside the chip, never leaves it. Flash holds only a public random salt (0x75000) |
| Key derivation (all credential keys and key-handle MACs, U2F and CTAP2) | HMAC-SHA256 on the RP2040 | HMAC-SHA256 **computed by the chip** over `salt ‖ data` |
| Randomness | on-chip noise + ROSC + timer | the same **plus** the chip's hardware RNG, mixed through SHA-256 |
| ECDSA signature of a credential | RP2040 | RP2040, with the key the chip derived for that one credential. The chip cannot hold unlimited keys |
| Attestation key, PIN hash | flash | **unchanged: still in flash** |

`authenticatorReset` in SE mode rotates the salt, so every credential is invalidated as before.

**Enrolling SE mode is one-way for the software identity.** At the first SE-mode boot the firmware stores the salt and the
chip serial and then ERASES the software master key (0x72000), so it can no longer be read from flash and removing the jumper
cannot bring the old identity back. Software-mode registrations are lost for good. The PIN record and the U2F counter are
kept; the counter never goes backwards when the mode changes. Removing the jumper later starts a fresh software identity
(new key, button press) - the SE salt stays, so re-fitting the jumper and the same chip restores the SE identity.

## Fail closed

If the jumper is present and anything below is wrong, the LED blinks N times, pauses, repeats, and the device
**never starts USB and never falls back to software crypto**.

| Blinks | Meaning |
|---|---|
| 1 | no ACK / bad wake answer (wiring, power, address) |
| 2 | answers, but is not an ATECC608 |
| 3 | config zone or data zone not locked |
| 4 | the root-secret slot can be read in clear |
| 5 | the root-secret slot is blank (all 0x00 / 0xFF) |
| 6 | CRC, status or timeout error during the checks |
| 7 | a different chip than the one enrolled (serial number mismatch) |

The chip serial is stored at the first SE-mode boot (button press, as in software mode) and checked at every boot.

## Preparing the chip (not done by this firmware)

The chip must be provisioned once with Microchip's tools (Trust Platform Design Suite or cryptoauthlib), with:
config and data zones **locked**; slot `SE_HMAC_SLOT` (default 0) holding a random 32-byte secret, usable with the
SHA/HMAC command, **not readable** and **not writable** after the lock. The firmware verifies the lock bits, that
the slot refuses a clear read, and that it is not blank. It cannot verify the other slot properties.

I deliberately did not ship config bytes or an on-device provisioning routine: locking is permanent, and I could
not validate any configuration against real silicon. Use a spare chip first.

## Limits (read before relying on it)

* **Unencrypted I2C.** Anyone probing the bus sees the HMAC outputs, i.e. the derived private key of every
  credential used while they watch. They do not see the root secret.
* **No rate limit in the chip.** Whoever holds the whole device can ask the chip to derive keys for handles they
  know. SE mode defeats copying the flash, not possession of the complete board.
* **No authentication of the chip.** A fake chip fitted before first enrolment is undetectable; swapping the chip
  afterwards is detected (blink 7).
* PIN hash and attestation key remain in flash. No side-channel or fault-injection hardening.
* Moving the jumper switches identity: registrations made in one mode do not work in the other.
* Tested against a protocol simulator written from the ATECC608 datasheet (framing, CRC, wake/sleep, statuses,
  HMAC through the SHA command), **not against a real chip**. In particular the driver reads each answer as a 2-byte head
  (count + first byte), then count-2 bytes, which is what Microchip's own `hal_i2c_receive` does for ATECC parts; the
  simulator models that read-pointer behaviour. Checked against the vendor HAL sources (`lib/hal` of cryptoauthlib):
  wake = address-0 write at 100 kHz (SDA low >= 60 us) + delay + 4-byte answer `04 11 33 43`; sleep = word address
  0x01; command word address 0x03; 7-bit address = configured 8-bit address >> 1. Checked against `lib/calib` too: SHA command layout (HMAC Start = mode 0x04 with the key slot in param2,
  Update = mode 0x01 with 64 bytes, HMAC End = **mode 0x02** on the ATECC608 with the remaining 0..63 bytes), status codes
  (0x00/0x03/0x0F/0x11/0xFF), revision byte 0x60 = ATECC608 family, command word address 0x03. A previous version sent
  HMAC End as mode 0x05 (the ATSHA204A/ATECC508A code) - that would have been refused by a real 608; fixed. NOT checked:
  the `wake_delay` default (not in the archives) - this driver waits 1.5 ms after wake and polls until the chip answers.

## Reference: CryptoAuthLib submodule (patch 0014)

`lib/cryptoauthlib` is Microchip's library (<https://github.com/MicrochipTech/cryptoauthlib>) pinned to commit
`d49c7d578efb09d4a498d5ab86839d4c17812f15` (version 3.8.0, main as of 2026-05-05). It is **not compiled into the
firmware**: `CMakeLists.txt` lists sources explicitly and does not touch `lib/cryptoauthlib`, so the binary is
unchanged. It is there as the pinned reference that `src/se.c` was checked against, and for the provisioning tools
(`python/`, `app/`) mentioned above.

* Fetch it: `git submodule update --init --depth 1 lib/cryptoauthlib` (or `git clone --recursive`).
* Move the pin: `git -C lib/cryptoauthlib fetch --tags && git -C lib/cryptoauthlib checkout <tag-or-sha>`, then
  `git add lib/cryptoauthlib` and commit.
* **Licence:** Microchip's `license.txt` allows use "exclusively with Microchip products" and requires its terms to be
  redistributed. Fidelio is GPL-2.0. Keeping the library as a separate submodule is fine; **linking its code into a
  firmware image you distribute would combine the two licences, which do not obviously fit.** For personal builds this
  does not arise. Ask a lawyer before shipping binaries that contain it.
