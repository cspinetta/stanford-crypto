# Stanford Crypto

My solutions (in rust) and notes while taking [Stanford's Cryptography I](https://www.coursera.org/learn/crypto) course by Dan Boneh.

I’m using this repo to deepen my understanding of how cryptographic primitives actually work.

Each week’s exercises live in a separate module under `src/`.

---

## Weekly Learnings

### Week 1 — One-Time Pad and Stream Ciphers
- Learned about PRG, perfect secrecy, and semantic security.
- Explored why key reuse completely breaks the one-time pad.
- OTP is malleable - modifications are *undetected* and have *predictable impact*.
- Weak PRGs (predictability).
- Insecure real-world stream ciphers: RC4, WiFi WEP Encryption, CSS.
- Secured real-world stream ciphers: Salsa20, ChaCha20
- Implemented simple byte-level XOR operations and frequency analysis for ciphertext recovery.

### Week 2 — Block Ciphers and Modes of Operation
- Introduced PRFs and PRPs as the abstraction behind block ciphers.
- Feistel networks and the Luby–Rackoff theorem (why ≥3 rounds are needed).
- AES as a concrete secure PRP (128-bit blocks).
- Why naive constructions (e.g., 2-round Feistel) are distinguishable from random.
- CBC mode: chaining, random IVs, and PKCS#5 padding.
- Subtle CBC pitfalls: reusing keys for IV derivation breaks CPA security.
- CTR mode: turning a block cipher into a stream cipher.
- Error propagation: CBC corrupts two blocks, CTR only one.
- Encryption leaks message length; ciphertext size matters.
- Implemented AES-CBC and AES-CTR decryption, including manual handling of IVs and counters.

Additional exercises and notes will be added as I progress through the course.

---

## License

This project is licensed under the [MIT License](LICENSE).
