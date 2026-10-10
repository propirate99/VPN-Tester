# Security & AI Claims Register

Every security or machine learning claim asserted by VajraNet AI must adhere to the **Claim, Evidence, and Limitation** model:

```text
CLAIM
EVIDENCE
LIMITATION
```

This prevents unsubstantiated claims and protects against overpromising in cybersecurity assessments.

---

## Registered Baseline Claims

### 1. Perfect Forward Secrecy
- **CLAIM:** PFS may be disabled on this tunnel.
- **EVIDENCE:** CREATE_CHILD_SA exchange lacks Key Exchange (KE) payload, or gateway configuration policy lacks DH groups.
- **LIMITATION:** ESP-only captures without IKE negotiations cannot establish whether PFS was negotiated.

### 2. Replay Protection
- **CLAIM:** Possible replay attack or sequence number duplication.
- **EVIDENCE:** Duplicate ESP sequence numbers observed under the same SPI.
- **LIMITATION:** Packet captures taken on mirroring taps can sometimes duplicate packets due to network switch configuration rather than an active adversary.

### 3. Cryptographic Suite Strength
- **CLAIM:** Insecure or legacy cryptographic algorithm negotiated.
- **EVIDENCE:** IKE Transform payload specifies DES, 3DES, or MD5.
- **LIMITATION:** Encrypted payloads cannot be read to verify cipher implementation correctness without endpoint log correlation.

### 4. Anomaly Detection
- **CLAIM:** Traffic profile deviates statistically from normal baseline.
- **EVIDENCE:** Isolation Forest score < 0 or packet rate exceeds 1,000 pkts/sec.
- **LIMITATION:** High throughput file transfers or backups can generate statistical outliers without representing malicious attacks (requires operator context).
