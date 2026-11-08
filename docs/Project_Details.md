# Q-Sentinel
## Eavesdropper-Aware BB84 Quantum Key Distribution for Secure Defence Communication

**Department of CSE (Cyber Security) | Course: 20CS31009 Cryptography | PBL**
**Language:** Java (Swing) | **Type:** Simulation (software model of the quantum channel)

---

## 1. Row for the class sheet (copy-paste)

| Column | Entry |
|---|---|
| Project Title | Q-Sentinel: Eavesdropper-Aware BB84 Quantum Key Distribution for Secure Defence Communication |
| CO's Mapping | 1, 2, 3, 4 |
| PO's Mapping | 1, 2, 3, 5 |
| PSO's Mapping | 1, 2 |
| SDG's | 9, 16 |

**Description / Expected Outcome (paste in the last column):**
The system simulates a complete Quantum Key Distribution link using the BB84 protocol. Alice sends photons in random bases, Bob measures them, and an eavesdropper (Eve) can intercept the line. The error rate (QBER) on a public sample reveals Eve and the key is discarded if QBER exceeds 11%. The classical channel is authenticated with HMAC-SHA256, errors are corrected, and SHA-256 privacy amplification produces a 256-bit key that drives AES-256-GCM encrypted messaging. The project also analyses QBER versus eavesdropping, demonstrates why classical Diffie-Hellman is vulnerable, and records every session in a SHA-256 hash-chained log.

---

## 2. Abstract
Key exchange schemes such as RSA and Diffie-Hellman depend on factoring and discrete-logarithm problems that a large quantum computer can solve using Shor's algorithm. Attackers can also record encrypted traffic today and decrypt it later. Quantum Key Distribution (QKD) addresses this by basing security on a physical law: measuring a quantum state disturbs it, so an eavesdropper necessarily introduces detectable errors. This project implements a full software model of QKD: the BB84 protocol, an authenticated classical channel, sifting, QBER-based eavesdropper detection, Cascade-style error correction, privacy amplification, and AES-256-GCM secure messaging. Experiments show the measured error rate rising linearly (about 25% x fraction of intercepted qubits) and crossing the 11% abort threshold, which validates the detection principle.

## 3. Real-world relevance
DRDO has completed military field trials of an indigenous fibre-based QKD system (with Taqbit Labs, Bengaluru) intended to secure critical strategic communication networks against future quantum-era threats. Earlier DRDO and DRDO-IIT Delhi demonstrations included QKD over more than 100 km of fibre and free-space entanglement-based QKD, and a DRDO lab demo showed detection of a third party trying to listen in. Q-Sentinel models the same protocol stages in software so that the principles can be studied and demonstrated.

## 4. Problem statement
Defence and strategic networks need encryption keys that cannot be silently copied. Existing public-key key exchange is mathematically secure only against classical computers and offers no way to know whether a key was intercepted. We need a key distribution method that **detects** eavesdropping and refuses to use a compromised key.

## 5. Objectives
1. Simulate the BB84 protocol with random bases, an intercept-resend eavesdropper and channel noise.
2. Detect eavesdropping by estimating QBER and aborting above 11%.
3. Authenticate the classical channel (HMAC-SHA256) to stop man-in-the-middle attacks.
4. Turn the sifted bits into a secure 256-bit key (error correction + privacy amplification).
5. Use the key for AES-256-GCM encrypted, tamper-evident messaging.
6. Compare with classical Diffie-Hellman and show why QKD matters.

## 6. Existing vs proposed system

| Existing (classical key exchange) | Proposed (Q-Sentinel / QKD) |
|---|---|
| Security from hard maths (factoring, discrete log) | Security from physics (measurement disturbs the state) |
| Breakable by Shor's algorithm on a quantum computer | No such mathematical shortcut |
| Cannot tell whether the key was copied | **Detects** eavesdropping through QBER and aborts |
| "Harvest now, decrypt later" is possible | Compromised key is never used, so nothing useful to decrypt later |
| Classical channel often unauthenticated in demos | Classical channel authenticated with HMAC-SHA256 |
| Key used as-is | Error correction + privacy amplification remove errors and Eve's partial knowledge |
| Logs editable | SHA-256 hash-chained session log |

## 7. Working (step by step)
1. **Photon exchange:** for each qubit Alice picks a random bit and a random basis (+ rectilinear or x diagonal) and sends a photon polarization (arrows in the table).
2. **Eve (optional):** intercepts a chosen fraction of photons, measures in a random basis (wrong basis gives a random result) and re-sends. This disturbs the state.
3. **Bob:** measures in a random basis; if his basis differs from the photon's, the result is random. Channel noise may flip bits.
4. **Authenticated announcement:** bases are announced over the classical channel with an HMAC-SHA256 tag. A modified announcement fails verification (MITM blocked).
5. **Sifting:** keep only qubits where Alice's and Bob's bases matched (about 50%).
6. **QBER test:** publicly compare a random 25% sample. QBER above 11% means an eavesdropper (or a very noisy line): the key is discarded.
7. **Secure-length check:** secure bits = raw x (1 - (1 + 1.05) x h(QBER)), where h is binary entropy and 1.05 is the Cascade efficiency. At least 256 secure bits are needed.
8. **Error correction:** Cascade-style block-parity comparison with binary search fixes Bob's errors; both ends confirm identical keys.
9. **Privacy amplification:** SHA-256 compresses the corrected key into a 256-bit key.
10. **Messaging:** AES-256-GCM encrypts messages; Eve's guessed key fails the authentication tag; tampering in transit is rejected.
11. **Audit:** every session is recorded in a SHA-256 hash chain.

## 8. Algorithms and techniques
BB84 (Bennett and Brassard, 1984), HMAC-SHA256, SHA-256, AES-256-GCM, Cascade-style error correction, privacy amplification, binary entropy bound, Diffie-Hellman (discrete log brute force demo), SHA-256 hash chain.

## 9. Syllabus mapping (20CS31009 Cryptography)

| CO | How it is covered | Unit |
|---|---|---|
| CO1 Group theory, rings, fields | Diffie-Hellman over Z_p, modular exponentiation and the discrete-logarithm problem | I, II |
| CO2 Hash functions for secure data transfer | HMAC-SHA256 channel authentication, SHA-256 privacy amplification, hash-chained log | IV |
| CO3 Symmetric/asymmetric algorithms for encryption | AES-256-GCM messaging; Diffie-Hellman key exchange comparison | III, IV |
| CO4 Cryptanalytic techniques | Intercept-resend attack on BB84, QBER analysis, brute-force discrete log on small DH | V |

## 10. Why this project is unique in the class
- Not a message, file, vault, QR, identity, voting, wallet, MFA, PKI or steganography project: it is the **key-distribution layer** itself.
- Nearest title on the sheet is *Post-Quantum Secure Communication*. That uses new mathematical problems that quantum computers cannot solve (software cryptography). Q-Sentinel uses **quantum physics to detect eavesdropping** (QKD). Different principle, different protocol, different results.
- Contains an **attacker model with measurable detection** (QBER chart), which no other project on the list has.
- Includes the **full QKD pipeline** (authentication, sifting, error correction, privacy amplification), not just the textbook BB84 table.
- Tip: before submitting, press Ctrl+F in the class sheet and search for "quantum", "BB84" and "QKD" to confirm nobody else has taken it.

## 11. Results (from the included tests)
| Scenario (4096 qubits) | Outcome |
|---|---|
| No Eve, 0-5% noise | Key accepted every time (200/200 runs per setting) |
| Eve intercepts 100% | Measured QBER about 25%, key aborted (100/100) |
| Eve intercepts 10% | QBER about 3%, key accepted, but Eve's guessed key still fails to decrypt (privacy amplification) |
| Classical channel tampered (MITM) | HMAC fails, aborted (50/50) |
| QBER vs Eve fraction | Measured values follow 25% x fraction within about 0.5% (see qber_experiment.csv) |

## 12. Limitations (be honest in the viva)
- It is a **simulation** of the quantum channel; there are no real photons or detectors.
- Only the intercept-resend attack is modelled (photon-number-splitting and other attacks are not).
- Authentication uses HMAC with a pre-shared key; real systems use information-theoretic (Wegman-Carter) authentication.
- Error-correction leakage is modelled with a standard efficiency factor (1.05).

## 13. Future scope
Decoy-state BB84, E91 (entanglement-based) protocol, Wegman-Carter authentication, multi-hop trusted-node networks, integration with a real QKD hardware API.

## 14. Likely viva questions
1. **What is QKD?** Distributing an encryption key using quantum states so that eavesdropping is detectable.
2. **Why does Eve cause errors?** She must measure; a wrong-basis measurement gives a random result and she re-sends a disturbed state. Bob then gets a wrong bit 25% of the time on matching bases.
3. **Why 25%?** Eve guesses the basis wrongly 50% of the time; then Bob's result is wrong 50% of those times: 0.5 x 0.5 = 25%.
4. **Why 11%?** Above about 11% QBER, no secret key can be distilled with one-way error correction and privacy amplification.
5. **Why authenticate the classical channel?** Otherwise a man-in-the-middle can impersonate both ends. We use HMAC-SHA256 with a pre-shared key.
6. **What is privacy amplification?** Hashing the key to a shorter one so that any partial knowledge Eve has becomes useless.
7. **Why not just use RSA/DH?** Shor's algorithm breaks them on a large quantum computer, and recorded traffic can be decrypted later.
8. **Does QKD replace encryption?** No. It distributes the key; AES (here AES-256-GCM) still encrypts the data.
9. **Is this real quantum?** It is a software simulation of the quantum behaviour (random outcome on wrong basis), as used in academic QKD studies.
10. **How is this different from post-quantum cryptography?** PQC is new mathematics on classical computers. QKD uses quantum physics and detects eavesdropping.

## 15. References
1. C. H. Bennett and G. Brassard, "Quantum cryptography: public key distribution and coin tossing", 1984 (BB84).
2. P. W. Shor, "Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer", 1994.
3. G. Brassard and L. Salvail, "Secret-key reconciliation by public discussion" (Cascade), 1993.
4. W. Stallings, Cryptography and Network Security (course textbook): AES, Diffie-Hellman, HMAC, SHA.
5. DRDO press statement and news reports on military field trials of indigenous QKD (July 2026).
