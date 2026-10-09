# Fidelio `atecc-support` — Bugs, Security Findings, and Design Limitations

**Repository:** https://github.com/rezamarzban/fidelio/tree/atecc-support  
**Scope:** Source-code review of the `atecc-support` branch, concentrating on CTAP2 PIN handling, persistent state, credential derivation, U2F counters, and Secure Element integration.  
**Review status:** Static source review only. These findings have not all been reproduced on hardware. In particular, the ATECC608 driver and failure paths need testing against the exact supported chip variant and configuration. Confirm every finding against the exact commit being evaluated before treating it as a verified defect in a release.

## Executive summary

The findings fall into three groups:

1. **Potential security bugs:** PIN-token state may be accepted after RNG failure; interrupted PIN-state writes may reset the retry count; and flash-stored Secure Element state may be rolled back to restore a previous credential identity.
2. **Functional and robustness bugs:** counter updates are not fully crash-consistent, CTAP2 may expose a shared cross-RP signature counter, PIN-verified requests may not set the UV bit correctly, `getAssertion` appears to consider only the first `allowList` descriptor, and some error returns bypass key-buffer cleanup.
3. **Design limitations rather than necessarily code defects:** the ATECC608 currently provides root-secret/KDF protection rather than hardware credential signing; several security-sensitive values remain in RP2040 flash; slot-policy checks are incomplete; and real-chip validation is outstanding.

Severity labels below reflect potential impact under the stated assumptions. They are not a substitute for reproducing a finding, reviewing the exact commit, and establishing the intended deployment threat model.

---

## 1. High-priority security findings

### SEC-01 — PIN token can be marked valid after random-number generation fails

**Severity:** High, conditional on RNG failure  
**Area:** CTAP2 PIN-token generation  
**File:** [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c)

#### Description

The source review found PIN-processing paths that call `wc_InitRng(&rng)` without consistently checking the return value, including paths associated with `getKeyAgreement`, `setPIN`, `changePIN`, and `getPINToken`.

More importantly, `pin_reset_token()` was observed to ignore the return value from `wc_RNG_GenerateBlock()` and set `pin_token_valid = true` unconditionally. If random generation fails, the token buffer may remain unchanged or otherwise fail to contain fresh unpredictable bytes, but the program can still mark it usable.

Static storage is zero-initialized in C. Therefore, on a fresh boot, a failure that leaves the buffer unchanged could leave an all-zero token marked valid. Whether a practical request can exploit this depends on the exact control flow and whether later checks reject the failed operation; it should be verified with fault injection.

#### Impact

If an invalid or predictable token is accepted, an attacker may be able to calculate `pinAuth` without knowing the user's PIN. This is a **conditional failure-path concern**, not evidence that normal PIN authentication can always be bypassed.

#### Recommended remediation

- Mark the token invalid and clear its buffer **before** attempting to generate a replacement.
- Check every `wc_InitRng()` and `wc_RNG_GenerateBlock()` result.
- Set `pin_token_valid = true` only after successful generation of fresh random data.
- Abort the current PIN operation on any RNG failure; never continue with a partially initialized RNG.
- Add tests that force RNG initialization and output generation to fail, then confirm no PIN token can be used and no operation requiring PIN authorization succeeds.

#### Verification test

Inject failures separately into RNG initialization and token generation. After each failure, submit a request with a `pinAuth` computed using the unchanged token buffer (including an all-zero buffer in a fresh-boot test). Expected behavior: the operation is rejected and the token remains invalid.

---

### SEC-02 — Interrupted PIN-state update can restore the retry counter

**Severity:** High, especially with physical power interruption  
**Area:** Persistent PIN state and retry-limit enforcement  
**File:** [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c)

#### Description

The reviewed `pin_state_save()` implementation erases the PIN-state sector and then programs the updated record. It does not preserve an independent valid copy of the old record until the new one has been durably written.

The corresponding load path, `pin_state_load()`, reportedly treats a missing magic value as an uninitialized record and restores the retry count to `PIN_MAX_RETRIES`.

This creates a power-loss window: a failed PIN attempt decreases the retry count, the firmware erases the sector, and power disappears before the new record is committed. On reboot, the missing record can be interpreted as a fresh/unconfigured state, potentially restoring the retry limit and/or losing the saved PIN-related state.

#### Impact

An attacker with the ability to interrupt power at carefully chosen moments may be able to repeat guesses beyond the intended retry limit. Even without an attacker, accidental brownouts can corrupt PIN state or make a configured PIN appear absent. The exact exploitable sequence should be verified on the current code and flash implementation.

#### Recommended remediation

- Store PIN state in a crash-consistent format, for example with two independent records/sectors.
- Include a monotonically increasing sequence number, integrity check (such as a MAC where a suitable key is available), and an explicit record state/version.
- Write and verify the new record before erasing or invalidating the previous valid record.
- Treat unexpected corruption or absence of an expected record as a recovery/error state, not automatically as a fresh PIN configuration with all retries restored.
- Keep the retry count update durable before deciding whether a PIN attempt is accepted or rejected.

#### Verification test

Use controlled power interruption at each flash operation: before erase, after erase, during programming, after programming but before verification, and before retiring the previous copy. On every reboot, confirm that the PIN state remains valid and the retry count never increases because of an incomplete write.

---

### SEC-03 — Secure Element reset may be reversible by restoring an old flash salt

**Severity:** High under a physical flash-manipulation threat model  
**Area:** Credential identity, reset semantics, anti-rollback  
**Files:** [`src/u2f.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/u2f.c), [`SE.md`](https://github.com/rezamarzban/fidelio/blob/atecc-support/SE.md), [`SECURITY.md`](https://github.com/rezamarzban/fidelio/blob/atecc-support/SECURITY.md)

#### Description

In Secure Element mode, the root secret is held by the ATECC608, but the salt/metadata used in credential derivation is stored in RP2040 flash. Reset reportedly rotates this flash-stored salt instead of changing the ATECC-held root secret.

If the effective credential key is derived from the retained ATECC root plus that salt and other stable inputs, rotating the salt changes the derived keys. However, it does not irreversibly revoke the old derivation inputs if an attacker can save and later restore the old flash record.

A possible physical attack sequence is:

1. Save the current salt/metadata record.
2. Execute reset, which writes a new salt and appears to invalidate the previous credentials.
3. Restore the saved old record to flash while continuing to use the same ATECC608.
4. Cause the authenticator to derive the old credential keys again.

This scenario assumes the attacker can manipulate RP2040 flash and that no other non-rollbackable state changes during reset. It is not a remote USB-only attack.

#### Impact

Reset may provide logical invalidation but not irreversible revocation against physical flash rollback. Old credentials could potentially become usable again after restoring the old state.

#### Recommended remediation

- Bind credential derivation to non-rollbackable state, such as an appropriately configured hardware monotonic counter or a carefully designed hardware-protected state-transition mechanism.
- Ensure reset advances or changes that state in a way that cannot be reversed by restoring RP2040 flash.
- Document precisely what reset guarantees against remote attackers versus an attacker with physical flash access.
- Test restoring every saved pre-reset flash record after a reset and verify that old credentials cannot reappear.

**Important:** A public salt in ordinary flash is not an anti-rollback mechanism by itself.

---

### SEC-04 — Interrupted Secure Element enrollment may leave the previous software master key intact

**Severity:** Medium–High, depending on mode-switch guarantees  
**Area:** Secure Element enrollment and identity transition  
**File:** [`src/u2f.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/u2f.c)

#### Description

The reviewed provisioning path in `flash_master_keygen()` appears to write the Secure Element salt and chip serial metadata before erasing the previous software master-key sector.

If power is interrupted after the new Secure Element record is committed but before the old software key is erased, the next boot may recognize the Secure Element record and skip first-time provisioning. The old software key can remain on flash. If the device can later be switched back to software mode (for example, by changing the mode jumper), the old identity may become available again.

This is particularly important if the documentation promises that Secure Element enrollment permanently destroys the previous software identity.

#### Impact

The transition may not be irreversible after power loss. The practical impact depends on how the mode selector is interpreted at boot and whether any additional migration state prevents fallback.

#### Recommended remediation

- Treat enrollment as a state machine with explicit, recoverable stages, such as `uninitialized`, `migration-in-progress`, and `SE-enrolled`.
- Ensure reboot recovery cannot reactivate the previous identity after enrollment has begun or been committed.
- Erase the old software key before committing a state that makes enrollment appear complete, or use a transaction design that safely recovers from interruption without re-enabling the old identity.
- Verify erased flash contents and record the final state before reporting success.
- Do not promise irreversible destruction unless the design ensures it under all supported power-failure scenarios.

#### Verification test

Cut power at every step of enrollment and then boot in both Secure Element and software modes. Confirm that no interrupted transition permits fallback to the old software master key.

---

## 2. Medium-priority functional, privacy, and robustness findings

### BUG-05 — A shared global counter can correlate activity across relying parties

**Severity:** Medium, privacy/interoperability concern  
**Area:** U2F and CTAP2 signature-counter behavior  
**Files:** [`src/u2f.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/u2f.c), [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c)

#### Description

The branch exposes a shared `U2F_Counter` through functions such as `device_get_counter()` and `device_counter_inc()`. The review found CTAP2 credential-creation/assertion paths using the same counter.

Because relying parties receive authenticator data containing the signature counter, different sites may observe values from a common sequence. If one site sees a counter value and another later sees a larger value, they can infer ordering or frequency of authentications across otherwise unrelated sites. Counter semantics and modern WebAuthn ecosystem expectations also need to be considered.

#### Impact

The shared counter can create cross-relying-party correlation and unnecessary privacy leakage. It can also produce compatibility issues if counter values unexpectedly reset or are shared by distinct credential flows.

#### Recommended remediation

- Decide on counter behavior separately for legacy U2F and CTAP2/WebAuthn.
- If compatibility and the intended design permit it, consider returning a zero signature counter for CTAP2 rather than exposing a global cross-RP sequence.
- Ensure whichever policy is chosen is consistently reflected in `authenticatorData` and documented.
- Add multi-RP tests showing the externally visible counter behavior.

This is mainly a privacy/design issue, not direct evidence of signature forgery.

---

### BUG-06 — Counter-sector update may fail after interrupted writes

**Severity:** Medium, reliability/integrity  
**Area:** Flash-backed U2F counter  
**File:** [`src/u2f.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/u2f.c)

#### Description

The counter uses two flash sectors. The review found that the update path writes the new value to a target page and then erases the other copy, while `write_counter_page()` does not itself ensure the target sector is erased before programming.

If power is interrupted after the new record is written but before the old one is erased, both copies may remain valid. On reboot, the loader reportedly selects the larger counter. The next update may try to program a sector containing the older record. Flash programming cannot turn a programmed zero bit back into one without erasing the sector, so the write can fail or corrupt the intended update.

The exact failure depends on the sector/page layout and programming API; it should be verified with targeted power-cut tests.

#### Impact

Counter updates may become stuck or inconsistent following a reset during an update. Incorrect recovery can also cause a counter to roll back, which can harm relying-party clone detection or compatibility.

#### Recommended remediation

- Add robust recovery when both records are valid.
- Use sequence numbers, a checksum/MAC, and explicit record versioning.
- Always erase a target sector before reuse, while preserving at least one verified valid record.
- Check every erase/program/verify result and fail safely if the counter cannot be updated.
- Inject power failure at every update stage and verify monotonic recovery.

---

### BUG-07 — PIN-authenticated requests may not set the CTAP2 User Verified (UV) flag

**Severity:** Medium, protocol-conformance issue  
**Area:** `authenticatorData` flags  
**File:** [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c)

#### Description

The reviewed make-credential and assertion code reportedly sets the UV flag only when `params.pin_auth_len == 16`. However, the branch supports PIN protocol 2, where `pinAuth` is 32 bytes.

If those observations match the current code path, successfully authenticated PIN-protected requests will not satisfy the 16-byte condition and may therefore produce authenticator data without the UV flag.

#### Impact

The authenticator can under-report successful user verification. Relying parties that require user verification may treat the operation as not verified or reject it, despite the PIN check having succeeded.

#### Recommended remediation

- Set the UV flag based on the validated authentication method/state, not a hard-coded `pinAuth` length unrelated to the active protocol.
- Keep protocol-specific length validation separate from the semantic UV decision.
- Test valid and invalid PIN requests under every supported PIN protocol for both `makeCredential` and `getAssertion`.
- Decode the returned authenticator data and assert the UP/UV flag values in automated tests.

---

### BUG-08 — `getAssertion` appears to inspect only the first `allowList` descriptor

**Severity:** Medium, interoperability/functional bug  
**Area:** CTAP2 `getAssertion` request parsing  
**File:** [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c)

#### Description

The reviewed `parse_getassert()` implementation appears to process the first credential descriptor and skip the remaining descriptors rather than checking the complete `allowList`.

An authenticator should be able to find a matching credential among the supported descriptors in the request. If the first descriptor is not available on the device but a later descriptor is valid, stopping after the first can incorrectly return `CTAP2_ERR_NO_CREDENTIALS`.

#### Impact

Valid authentication attempts can fail when clients provide multiple credential descriptors. The issue can appear as inconsistent browser/client compatibility, even though the device holds one of the requested credentials.

#### Recommended remediation

- Parse and validate the entire `allowList` array within supported size limits.
- Iterate through candidate descriptors and check supported type, identifier, and relying-party binding.
- Return a matching assertion when an allowed credential is found; return `NO_CREDENTIALS` only after all supported candidates have been checked.
- Add tests where the matching credential appears first, in the middle, last, or is absent. Include unsupported descriptor types and malformed CBOR.

---

### BUG-09 — Some error paths do not wipe derived private-key buffers

**Severity:** Medium–Low, secret-lifetime/hardening problem  
**Area:** Credential-key derivation and cleanup  
**File:** [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c)

#### Description

In `ctap2_get_assertion()`, the credential private key is derived into a local buffer named `private`. Some subsequent failure paths reportedly return directly without reaching the normal `ForceZero(private, sizeof(private))` cleanup. Identified examples include credential-handle verification failure, user-presence timeout, and RNG initialization failure.

A similar cleanup gap may exist if credential creation fails in `build_credential_id()` after a private key has been partly derived.

#### Impact

Private-key material can remain in stack/RAM memory longer than necessary. This does not by itself establish a remote key-extraction vulnerability, but it increases exposure to subsequent memory-disclosure bugs, debugging interfaces, crash dumps, or other fault scenarios.

#### Recommended remediation

- Use a single cleanup path for functions that handle private keys and secret intermediates.
- Ensure every exit after secret initialization wipes those buffers with a non-optimizable zeroization routine.
- Clear derived keys immediately after signing or when any operation fails.
- Review the handling of HMAC outputs, PIN tokens, decrypted secrets, and other temporary key material using the same rule.
- Add tests or static-analysis checks to identify direct returns that bypass cleanup.

---

## 3. Secure Element design limitations (not all are code bugs)

### DESIGN-10 — ATECC608 protects the root/KDF operation, but does not perform credential signing

**Severity:** High relative to a goal of protecting credential keys from MCU compromise  
**Area:** Cryptographic architecture  
**Files:** [`SE.md`](https://github.com/rezamarzban/fidelio/blob/atecc-support/SE.md), [`src/se.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/se.c)

#### Description

In the current design, the ATECC608 is used as a protected root-secret/HMAC-KDF device. Derived credential private-key bytes are returned to the RP2040, and the RP2040 performs the actual software ECDSA signature operation.

The I²C link is not encrypted. An observer able to monitor the bus during derivation can potentially capture HMAC outputs that are used as private keys. A compromised RP2040 firmware can also access the derived key when it is present in RAM.

This architecture therefore protects the root secret and makes simple flash cloning harder, but it does **not** provide the strongest property offered by a Secure Element: keeping the credential private key inside the chip while performing the signature internally.

#### Impact

A firmware compromise or suitable I²C observation can defeat the confidentiality of derived credential private keys even when the ATECC root itself cannot be read through ordinary commands.

#### Recommended remediation

- For credentials requiring the strongest protection, generate/store a P-256 private key in an appropriate ATECC608 slot and use its hardware `Sign` command.
- The RP2040 should send only the digest and receive the signature; it should never receive the private key.
- Keep software signing for algorithms that the ATECC608 does not support, but clearly separate those credentials and disclose their weaker key isolation.
- Review slot policy, key configuration, command permissions, and provisioning before relying on the hardware-signing path.

**Algorithm note:** ATECC608 hardware signing is based on ECDSA P-256/ES256. It does not directly implement Ed25519, ES384, ES512, or ML-DSA.

---

### DESIGN-11 — Secure Element initialization does not prove every security-sensitive slot policy

**Severity:** Medium, provisioning/configuration risk  
**Area:** ATECC608 provisioning and slot policy  
**Files:** [`SE.md`](https://github.com/rezamarzban/fidelio/blob/atecc-support/SE.md), [`src/se.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/se.c)

#### Description

The initialization code reportedly checks that the chip responds, that configuration/data zones are locked, that reading the designated root-secret slot in clear fails, and that the slot is not obviously blank. The documentation also acknowledges that the firmware cannot verify every relevant security property of the slot.

These checks do not necessarily establish that the root slot's write policy, key type, permitted commands, derivation configuration, and other security-relevant configuration bits exactly match the intended profile.

#### Impact

A misprovisioned or incorrectly configured ATECC608 may pass basic checks while providing weaker guarantees than expected. Since the chip's configuration can be variant- and provisioning-specific, software checks should not assume an arbitrary locked chip is correctly configured.

#### Recommended remediation

- Define a canonical configuration profile for each supported chip/variant and document the required configuration bytes and slot policies.
- Validate all readable configuration fields against that profile wherever practical.
- Check relevant key type, slot permissions, lock state, and permitted operations against the exact device datasheet and CryptoAuthLib behavior.
- Provision and verify devices through a reproducible tool/process, and retain an auditable provisioning record.
- Test deliberately misconfigured chips and ensure initialization fails closed.

---

### DESIGN-12 — Attestation key and PIN verifier remain in RP2040 flash

**Severity:** High for physical flash-dump resistance; threat-model dependent  
**Area:** Secret storage  
**Files:** [`src/cert.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/cert.c), [`src/ctap2.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/ctap2.c), [`SECURITY.md`](https://github.com/rezamarzban/fidelio/blob/atecc-support/SECURITY.md)

#### Description

Enabling Secure Element mode does not move every sensitive value into the ATECC608. The review notes that the attestation private key is compiled into the RP2040 firmware/flash through `src/cert.c`, while the PIN verifier/state remains in RP2040 flash.

A flash dump can therefore expose the attestation private key if it is embedded there as described. A stored PIN hash or verifier may also allow offline guessing if it is based on a short numeric PIN and does not use a suitable keyed or memory-hard verification design. The precise risk depends on the exact PIN-verification construction and whether the stored verifier can be used to validate guesses offline.

#### Impact

Protecting the ATECC root secret alone does not protect unrelated secrets stored in firmware or flash. In particular, an exposed attestation private key may allow impersonation of the device's attestation identity, depending on how that key and certificate are used.

#### Recommended remediation

- Decide which keys need hardware isolation and store the attestation signing key in an appropriate ATECC608 slot if compatible with the intended attestation algorithm and certificate workflow.
- Avoid treating a flash-stored PIN hash as a defense against a physical attacker who can dump flash.
- Review the exact PIN verifier against CTAP requirements and the intended offline-guessing threat model.
- Clearly document what flash extraction reveals in both software and Secure Element modes.

---

### VALIDATION-13 — Driver and error paths need real-chip validation

**Severity:** Release-blocking validation gap for a hardware-dependent feature  
**Area:** ATECC608 driver and system robustness  
**Files:** [`SE.md`](https://github.com/rezamarzban/fidelio/blob/atecc-support/SE.md), [`src/se.c`](https://github.com/rezamarzban/fidelio/blob/atecc-support/src/se.c)

#### Description

The branch documentation states that the custom ATECC608 driver has been checked against CryptoAuthLib/reference behavior but has not been tested on real silicon. Source inspection and a protocol-level comparison cannot establish all real-device timing, wake/sleep, bus, configuration, and failure behavior.

Areas requiring hardware verification include wake response timing, sleep/idle behavior, I²C error recovery, SHA/HMAC command sequencing and block handling, slot permissions, response parsing/CRC validation, and recovery after interrupted transactions.

#### Impact

The driver may fail on actual hardware or in edge cases even if packet construction matches the reference implementation. Security assumptions depending on fail-closed behavior remain unproven until tested on the exact chip/variant.

#### Recommended remediation and test plan

1. Verify HMAC outputs against independent known-answer test vectors, including empty, short, block-boundary, and multi-block inputs.
2. Test wake, sleep, idle, reset, repeated commands, and bus recovery on every supported chip variant.
3. Test locked, blank, misconfigured, unreadable, and unavailable slots; initialization must fail closed where required.
4. Test malformed responses, CRC errors, NACKs, timeouts, chip removal, and recovery.
5. Interrupt power during enrollment, reset, PIN-state changes, and counter updates.
6. Run complete CTAP2/FIDO2 flows with real clients after hardware tests pass.
7. Record the chip model/revision, configuration-zone contents, firmware commit, and test results so that the evidence is reproducible.

---

## 4. Suggested repair order

| Priority | Finding | Main action |
|---|---|---|
| P1 | SEC-01 — Token marked valid after RNG failure | Make token generation fail closed; test RNG-failure injection |
| P1 | SEC-02 — PIN retry count can be lost on power failure | Implement crash-consistent PIN storage |
| P1 | SEC-03 — Salt rollback may restore old credentials | Add non-rollbackable hardware-bound state |
| P1 | SEC-04 — Enrollment interruption may preserve software identity | Make mode transition recoverable and irreversible |
| P2 | BUG-06 — Counter update crash consistency | Fix record/sector rotation and recovery |
| P2 | BUG-07 — UV flag condition | Base UV flag on successful verified PIN state |
| P2 | BUG-08 — Only first `allowList` entry | Parse and check all supported descriptors |
| P2 | BUG-09 — Private-key cleanup gaps | Centralize cleanup and zeroize on every exit |
| P2 | BUG-05 — Shared counter leaks cross-RP ordering | Define separate U2F/CTAP2 counter behavior |
| P2 | DESIGN-11 — Slot-policy validation is incomplete | Verify a canonical provisioning profile |
| Before release | VALIDATION-13 — No real-silicon validation | Run hardware, fault-injection, and end-to-end tests |
| Architecture decision | DESIGN-10 — Derived keys leave ATECC | Add hardware `Sign` for selected ES256 credentials |
| Architecture decision | DESIGN-12 — Other secrets remain in flash | Protect or explicitly accept exposure of each secret |

---

## 5. Overall assessment

The branch includes meaningful security work, but a few failure-handling and persistence paths deserve priority before the implementation is relied upon for important accounts. The most urgent code-level checks are the RNG/token path and crash-consistency of PIN state. The most important architectural caveat is that the current ATECC608 integration protects the root secret but exports derived credential private keys to the RP2040; it should not be described as hardware credential signing.

Recommended next steps:

1. Re-check each finding against the exact branch commit and confirm it is still present.
2. Fix the PIN-token RNG handling and persistent-state issues first.
3. Add power-loss and fault-injection tests for all flash transactions.
4. Define the intended physical-access threat model and reset guarantees.
5. Validate the driver on real ATECC608 hardware.
6. If resistance to compromised RP2040 firmware is a primary goal, implement and test a hardware-signing path that returns signatures but never exports signing private keys.

**Review limitation:** This document records source-review findings and hypotheses that require validation. It does not claim that every listed issue has been reproduced, nor that the repository has undergone a complete formal security audit.
