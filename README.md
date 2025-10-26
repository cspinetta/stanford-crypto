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

Additional exercises and notes will be added as I progress through the course.

---

## License

This project is licensed under the [MIT License](LICENSE).
