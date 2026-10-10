# Security Policy & Assessment Framework

## Core Principles

The security assessment in VajraNet AI is grounded in the **CIA Triad**:
- **Confidentiality:** Ensuring packet payloads are protected by approved strong encryption (e.g. AES-256, ChaCha20-Poly1305).
- **Integrity:** Ensuring packets cannot be modified in transit without detection (e.g. HMAC-SHA-256, AEAD).
- **Availability & Authenticity:** Ensuring connections are authenticated securely and protected against Denial of Service or replay attacks.

---

## 🔒 Security Baseline

VajraNet verifies VPN traffic against the following rules:

1. **Perfect Forward Secrecy (PFS):**
   - Each Child SA must generate independent keying material via a fresh Diffie-Hellman exchange during rekeys, preventing past sessions from being decrypted if long-term keys are compromised.

2. **Anti-Replay Protection:**
   - ESP sequence numbers must be monotonically increasing. Duplicate or out-of-window sequence numbers indicate replay attempts or misconfigured anti-replay windows.

3. **Approved Cryptographic Algorithms:**
   - Deprecated algorithms (DES, 3DES, MD5, SHA-1) are flagged as HIGH severity.
   - Only modern AES (CBC/GCM) or ChaCha20 suites are approved.

4. **Security Association Lifetime:**
   - Long-lived SAs without rekeying increase exposure to cryptanalytic attacks and sequence number exhaustion.

5. **IKE Negotiation Stability:**
   - Excessive IKE_SA_INIT packets without IKE_AUTH indicate authentication failure storms, pre-shared key mismatches, or unreachable responders.
