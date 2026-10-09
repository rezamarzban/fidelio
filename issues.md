# `picoECC` Branch — Bugs, Problems, and Security Limitations

## Scope and confidence

This report consolidates the findings from the static source review of the `picoECC` branch and incorporates the subsequent corrections. It describes issues identified in the reviewed source snapshot; it is **not** a guarantee that every issue has been found. No build or test on real ATECC608 hardware was performed as part of that review. Hardware behavior, provisioning assumptions, and the complete CTAP/U2F interoperability status therefore remain to be confirmed.

Severity labels used here:

- **High** — can undermine a security property or cause important authenticator operations to fail.
- **Medium** — protocol conformance, interoperability, or reliability problem.
- **Low** — limited reliability or maintenance concern.
- **Architectural limitation** — a consequence of the design rather than necessarily a code defect.

---

## A. High-priority bugs

### 1. UV flag condition uses the wrong `pinAuth` length

**Severity:** High — FIDO2 behavior / interoperability

The implementation correctly requires a 32-byte `pinAuth` for PIN/UV Auth Protocol 2. However, the MakeCredential and GetAssertion paths contain a separate condition that sets the User Verification (UV) flag only when `pin_auth_len == 16`.

Because this branch accepts Protocol 2 and expects a 32-byte authentication parameter, that condition is not satisfied for a valid Protocol 2 request. PIN verification and UV-flag construction are separate steps; passing the PIN check does not automatically set the UV flag in authenticator data.

**Impact:** An operation may pass the PIN-authentication check but return authenticator data without the expected UV flag. A relying party that requires user verification may reject the result.

**Recommended fix:** Make the UV-flag condition consistent with the protocol actually supported, and add tests that inspect the authenticator-data flags for successful PIN-authenticated MakeCredential and GetAssertion operations. Do not change the Protocol 2 `pinAuth` length from 32 bytes to 16 bytes; that earlier interpretation was incorrect.

### 2. ATECC608 `SlotConfig` validation checks the wrong field semantics

**Severity:** High — hardware configuration validation

The ATECC608 `SlotConfig` word contains distinct fields: `ReadKey` in bits 0–3, `WriteKey` in bits 8–11, and `WriteConfig` in bits 12–15. The reviewed code uses masks such as `0x0100` and `0x0200` as if individual bits in the `WriteKey` nibble directly indicated required or prohibited write modes. It also fails to validate `WriteConfig` itself.

`WriteKey` is a multi-bit field whose value selects a write policy; the individual bits should not be treated as independent Boolean capability flags. The resulting checks can reject a valid chip configuration—for example, the reviewed Microchip sample configuration with `WriteKey = 0`—while failing to enforce the intended write policy. A successful `se_init()` consequently does not prove that the chip has the intended key-generation and key-write restrictions.

**Impact:** The firmware can reject valid configurations or accept configurations that do not provide the security properties it assumes.

**Recommended fix:** Decode the complete `WriteKey` and `WriteConfig` fields according to the exact ATECC608 configuration specification. Validate each credential and attestation slot against an explicit, reviewed policy. Test the checks against known-good and deliberately unsafe configuration images, and confirm the expected result with a real chip.

### 3. PIN persistence is not atomic

**Severity:** High — PIN protection can be lost after interruption

The PIN record is saved by erasing a flash sector and programming the replacement record in that same sector. There is no transactional second copy that remains valid during the update. If power is lost, or programming fails, between erase and completion, the existing record may be destroyed.

On a subsequent boot, an invalid or missing magic value can be interpreted as “no PIN configured.” Since operations are permitted when no PIN is configured, a damaged record can turn a configured-PIN state into a no-PIN state rather than a locked or recovery-required state.

**Impact:** A power interruption or flash error can silently remove PIN protection. This is especially serious if an attacker can deliberately interrupt power during a PIN-state update.

**Recommended fix:** Use a recoverable update scheme, such as two records in separate erase units with version, sequence number, integrity check, and a commit marker. Write and verify the new record before selecting it as current. If records are invalid or inconsistent, fail closed; do not silently interpret corruption as “PIN not set.”

### 4. PIN-state save failures cannot be reported to callers

**Severity:** High — security-state reliability

`pin_state_save()` returns `void`, and its callers do not receive a success/failure result. Security-sensitive operations therefore cannot distinguish a successfully persisted state from a failed flash operation.

This affects changes such as setting or changing a PIN and updating the retry counter. In particular, retry-counter updates are security-relevant: if a decrement is not persisted, a reset or power interruption may restore an older retry count.

**Impact:** The authenticator may report success even though the state it relies on was not durably saved. The risk is compounded by the non-atomic storage design in Issue 3.

**Recommended fix:** Make persistence return an explicit status, propagate errors to the caller, verify the programmed record, and define safe behavior for failures. Do not report a PIN change or retry-state update as successful unless its durable commit has been confirmed.

### 5. PIN-related RNG initialization failures are unchecked

**Severity:** High / Medium — depends on the affected operation

The reviewed code calls `wc_InitRng()` in several PIN-related paths without checking its return value. Initializing an RNG can fail; callers must not proceed as though the generator is ready when initialization has failed.

**Impact:** A PIN operation may continue in an invalid error state. Depending on the downstream code and the state of the RNG object, subsequent generation can fail or return unusable output.

**Recommended fix:** Check every `wc_InitRng()` result. On failure, abort the operation, leave affected tokens invalid, clean up any initialized resources safely, and return an appropriate CTAP error. Exercise these paths with fault injection or a test wrapper that forces RNG initialization to fail.

### 6. PIN-token generation errors are ignored

**Severity:** High / Medium — security-state correctness

`pin_reset_token()` ignores the return code from `wc_RNG_GenerateBlock()` and sets `pin_token_valid = true` unconditionally. If generation fails, the token buffer is not guaranteed to contain fresh random bytes; it could retain zeroed, stale, or partially changed contents.

**Impact:** Data that has not been established as a successfully generated token can be marked valid. It is not correct to state that it will necessarily be all zeros; the buffer's actual contents depend on prior state and the failure mode.

**Recommended fix:** Invalidate the token before attempting generation. Check the generation result and set the validity flag only on success. On failure, clear the buffer, keep the token invalid, and abort the operation.

### 7. ATECC configuration checks do not cover all security assumptions

**Severity:** High / Medium — hardware provisioning assurance

Beyond the incorrect `SlotConfig` logic in Issue 2, `se_init()` checks only part of the configuration that influences how the selected key slots can be read, written, generated, or used. The firmware relies on assumptions about private-key slots, public-key retrieval, GenKey behavior, and restrictions on importing or replacing private keys, but it does not comprehensively prove all those properties from the device configuration.

**Impact:** Initialization may succeed even if the actual chip configuration differs from the configuration assumed by the firmware.

**Recommended fix:** Define a complete per-slot configuration policy and validate every field required by that policy, including the relevant `SlotConfig` and `KeyConfig` settings. Keep validation separate from provisioning, document the supported configuration images, and test both expected and rejected configurations on hardware.

---

## B. CTAP2 / FIDO2 protocol and behavior problems

### 8. MakeCredential `excludeList` is not implemented

**Severity:** Medium — protocol conformance / credential-creation behavior

The MakeCredential parser does not implement a check of the `excludeList`; the field is effectively skipped or ignored. The purpose of this list is to let a relying party identify credentials that already exist and prevent another credential from being created in circumstances where the authenticator can recognize a match.

**Impact:** The authenticator may create a credential even when the request asks it to detect an existing credential. This can violate expected WebAuthn behavior and cause compatibility or security-policy problems for relying parties.

**Recommended fix:** Parse the list and check every descriptor that the authenticator can support. Return the prescribed CTAP status when a matching credential is found. Add tests for empty lists, a match in the first position, a match in a later position, and no match.

### 9. GetAssertion considers only the first `allowList` descriptor

**Severity:** Medium — interoperability

The reviewed code explicitly selects the first descriptor and skips the remaining list entries rather than searching for a credential it can satisfy. An `allowList` can contain multiple credential descriptors, any supported matching entry may be relevant.

**Impact:** A valid credential later in the list can be ignored, causing GetAssertion to fail even though the authenticator holds a credential accepted by the request.

**Recommended fix:** Iterate through all supported descriptors, validate each one, and select a matching stored credential. Test with multiple entries where the match is first, middle, last, or absent.

### 10. Temporary PIN ECDH private key remains in RAM longer than necessary

**Severity:** Low / Medium — memory-hygiene concern

The ephemeral private key created for PIN key agreement is not cleared immediately after the shared secret has been derived. The reviewed flow marks the agreement key as consumed, but the private-key object can remain in RAM until it is replaced or the surrounding state is reset.

**Impact:** The key is not a credential private key and this does not by itself demonstrate a remote compromise, but unnecessary retention increases the amount of sensitive ephemeral material available to a memory-disclosure or firmware-debugging attacker.

**Recommended fix:** After ECDH and any required cleanup, explicitly zeroize and free the ephemeral private-key object as appropriate for the wolfCrypt API. Ensure error paths also clear it. Preserve the public agreement key only for as long as protocol behavior requires.

---

## C. U2F protocol validation problems

### 11. U2F APDU declared length is not checked against the received payload

**Severity:** Medium — input validation / protocol conformance

The APDU contains a declared length field, but the reviewed parsing path calculates the payload length from the received HID message and does not validate that this length agrees with the APDU's declared length.

**Impact:** Malformed or internally inconsistent APDUs may be accepted and interpreted differently from how the sender intended. This weakens protocol validation and increases the chance of edge-case parsing errors.

**Recommended fix:** Parse the APDU length field according to the APDU form supported by the implementation, compare it against the actual received payload length, and reject truncated, overlong, or inconsistent messages before dispatching the command.

### 12. U2F REGISTER accepts payloads longer than the expected request

**Severity:** Medium — input validation / protocol conformance

The reviewed REGISTER handler checks only that the payload is at least the expected minimum size (`len < 64` is rejected), rather than enforcing the exact length required by the supported command format.

**Impact:** Extra trailing bytes may be accepted even though they do not belong to a valid REGISTER request. That can produce inconsistent behavior across implementations and makes strict validation harder to reason about.

**Recommended fix:** Enforce the precise request length and field layout for the implemented U2F APDU format. Reject unexpected trailing data unless the standard explicitly permits it.

### 13. U2F parameter validation is incomplete

**Severity:** Medium — protocol conformance

The reviewed handlers do not validate all command parameter fields. In particular, REGISTER's fixed parameter values are not comprehensively checked, and the AUTHENTICATE path does not validate `p2` even though it checks supported values of `p1`.

**Impact:** Requests with reserved or unsupported parameter values may be processed instead of rejected. This is primarily a standards-compliance and robustness concern, not evidence of private-key extraction.

**Recommended fix:** Validate CLA, INS, P1, P2, APDU length, and all command-specific fixed or reserved fields before performing any cryptographic operation. Add negative tests for each invalid value.

### 14. Extra data is not consistently rejected in U2F requests

**Severity:** Medium — input validation / protocol conformance

Some U2F request handlers accept longer-than-expected payloads instead of requiring a well-formed request. This overlaps with the APDU-length and REGISTER-length problems above, but should be addressed across the command-dispatch layer rather than patched only in one handler.

**Impact:** Malformed inputs can reach deeper command-processing logic, increasing ambiguity and reducing interoperability with stricter implementations.

**Recommended fix:** Centralize APDU framing and length validation, then enforce exact command-specific payload lengths at each handler. Avoid silently ignoring data that the APDU format does not permit.

---

## D. Responsiveness and low-level reliability

### 15. `CTAPHID_CANCEL` does not interrupt a synchronous operation

**Severity:** Medium — responsiveness / denial-of-service resilience

The code's cancellation handler effectively does nothing because user-presence handling is synchronous and blocking. During a long button wait, the main flow may not be able to receive and act on a CANCEL message until the current operation returns.

**Impact:** A host may be unable to cancel promptly and the authenticator can remain busy for the duration of a user-presence wait (reported as up to roughly 30 seconds). This is primarily a responsiveness and availability problem; it is not, by itself, a key-extraction bug.

**Recommended fix:** Make the presence wait periodically service HID input or redesign the operation as a cancellable state machine. Ensure cancellation stops the pending operation, discards intermediate state, and returns the protocol-prescribed behavior.

### 16. ATECC I²C retry loop can block for several seconds when the bus is stuck

**Severity:** Medium — reliability / availability

The reviewed read loop may try up to 300 times, with an I²C timeout of about 20 ms and a 2 ms delay between attempts. If each transaction reaches its timeout, the rough upper-bound calculation is `300 × (20 ms + 2 ms)`, or about 6.6 seconds, ignoring other overhead. In ordinary NACK cases, failures generally return faster, so this is a worst-case stuck-bus estimate rather than the expected delay for every I²C error.

**Impact:** A stuck bus or repeated timed-out transactions can leave the authenticator unresponsive for several seconds.

**Recommended fix:** Use a bounded total deadline rather than a large retry count alone. Distinguish quick NACKs from bus timeouts, attempt controlled bus recovery where appropriate, and return a clear error once the deadline expires.

### 17. `se_sleep()` ignores I²C write failure

**Severity:** Low — low-level reliability

The reviewed `se_sleep()` helper discards the result of the I²C write that requests the ATECC to enter Sleep mode. Callers cannot tell whether the command was delivered.

**Impact:** The firmware's assumed device state may differ from the actual chip state. The impact depends on later command handling and recovery; this is not, by itself, evidence of a signing-key compromise.

**Recommended fix:** Return a status from `se_sleep()`, check it at call sites, and define recovery behavior if the command fails. Avoid assuming that a state transition occurred when the bus operation failed.

---

## E. Documentation and design limitations

### 18. README does not match the current implementation

**Severity:** Medium — maintenance / user expectations

The README reportedly still refers to obsolete items such as `mkcert.sh`, a master-key design, unlimited credential capacity, and cloning the original `danielinux` repository, while the current branch has a different implementation and credential-storage model.

**Impact:** Developers may follow stale setup instructions, misunderstand key management or credential limits, or assume capabilities that the branch no longer provides.

**Recommended fix:** Update the README to describe the current branch, prerequisites, hardware wiring, provisioning steps, supported protocol features, credential limit, reset behavior, build process, and known limitations. Remove obsolete commands and claims. Keep README and `SE.md` consistent.

### 19. PIN-protocol cryptography is performed in software, not entirely inside ATECC608

**Type:** Architectural limitation, not necessarily a code bug

The credential and attestation ECDSA signing operations use the ATECC608, but the reviewed PIN protocol also performs operations on the RP2040 using software cryptography, including ECDH and PIN-protocol key derivation/encryption/authentication (for example, wolfCrypt-based ECDH, HKDF, AES, and HMAC paths).

**Impact:** The claim that *all* cryptographic operations happen inside the secure element would not be accurate for this branch. The narrower statement that credential/attestation private-key signing is hardware-backed is more accurate.

**Recommended action:** State the security boundary explicitly in `SE.md` and other documentation. If the project requirement is literally to execute all cryptography inside ATECC608, that would require a design change and a feasibility review; it cannot be achieved merely by changing the wording.

### 20. RP2040 firmware can request signatures over arbitrary digests

**Type:** Architectural limitation, not necessarily a code bug

The ATECC protects the private key from being exported, but the firmware decides which slot to use and which digest to submit for signing. The ATECC does not independently understand or enforce WebAuthn semantics such as the RP ID, origin, credential ID, or whether a user-presence ceremony was properly completed.

**Impact:** If the RP2040 firmware is compromised or replaced, malicious firmware may be able to use the ATECC as a signing oracle for keys in accessible slots. Hardware key non-exportability is not the same as independent authorization of each signing operation.

**Recommended action:** Document this threat-model boundary. To address malicious-firmware attacks, consider a trustworthy firmware-update and secure-boot strategy, firmware integrity protections, and hardware configuration that constrains access as far as the platform permits. Do not claim that ATECC alone prevents unauthorized use by compromised firmware.

### 21. Real-ATECC608 validation remains outstanding

**Type:** Validation gap, not a demonstrated code bug

The reviewed branch has not been validated on real ATECC608 hardware as part of this assessment. Static inspection cannot establish that the selected device configuration, provisioning procedure, I²C timing, GenKey, public-key retrieval, Sign, and error recovery all work as expected on the target hardware.

**Impact:** Some hardware-dependent assumptions may remain unverified even if the source code appears internally consistent.

**Recommended action:** Test on the intended chip revision and board, record the device configuration, exercise success and failure paths, and verify generated signatures independently. Include power-interruption and I²C-fault tests for the storage and recovery paths.

---

## F. Items reviewed that should not be reported as bugs based on the available evidence

- **Protocol 2 `pinAuth` length:** Requiring 32 bytes is correct for this branch's PIN/UV Auth Protocol 2 implementation. The bug is the separate 16-byte check used for the UV flag (Issue 1), not the 32-byte validation.
- **`pin_shared_secret()` call count:** The claim that it is called twice for one subcommand was incorrect. The reviewed flow calls it once per relevant subcommand, and the reported `python-fido2` `setPIN` and `getPINToken` tests passed.
- **Certificate expiration in 2049:** This is not a current bug. It is a future maintenance date, not a present failure.
- **Discarding CTAPHID channel 0:** This behavior is consistent with the protocol and should not be listed as a bug on the available evidence.
- **Eight-byte certificate serial number:** No defect was established from the reviewed source solely on this basis.
- **Credential-table write ordering:** The reviewed implementation was assessed as recoverable; no definite bug was established in that specific ordering.
- **Seven-credential limit:** The limit is documented in `SE.md`, so it should not be described as wholly undocumented. The separate problem is that stale README claims need to be reconciled with the current design (Issue 18).
- **Software PIN cryptography:** This is a design limitation relative to an “all crypto in ATECC” goal, not automatically a vulnerability by itself (Issue 19).

---

## Recommended remediation order

1. Correct `SlotConfig` validation and test it against known-good and rejected ATECC608 configurations.
2. Fix the UV flag condition while keeping Protocol 2's 32-byte `pinAuth` requirement.
3. Make PIN storage recoverable and fail closed on corrupted or unreadable state.
4. Check and propagate all flash and RNG failures; never mark an ungenerated token valid.
5. Complete ATECC slot/configuration validation and test provisioning and signing on real hardware.
6. Implement `excludeList`, search the full `allowList`, and harden U2F APDU/parameter validation.
7. Improve cancellation and I²C timeout/recovery behavior.
8. Bring README and security documentation into line with the actual implementation and threat model.

**Overall assessment:** The reviewed branch has a useful hardware-backed signing architecture, but the configuration-validation and PIN-state issues should be corrected before treating it as security-hardened. Static review alone cannot substitute for hardware tests or CTAP/U2F conformance testing.
