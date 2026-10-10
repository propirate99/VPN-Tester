# Threat Model for IPsec VPNs

## 🎯 Threat Agents & Vectors

1. **Replay Attacks:**
   - Attacker captures valid ESP packets and retransmits them to cause resource consumption or unintended state changes.
   - *Defense:* Anti-replay window tracking and sequence number validation.

2. **Downgrade / Weak Cryptographic Attacks:**
   - Negotiating legacy ciphers (DES, 3DES, MD5) vulnerable to collision or brute-force attacks.
   - *Defense:* Enforce policy baselines restricting allowed algorithms.

3. **Session Compromise (Lack of PFS):**
   - If long-term private keys are compromised, an adversary who recorded historical traffic can decrypt past sessions unless Perfect Forward Secrecy was active.
   - *Defense:* Require ephemeral Diffie-Hellman key exchanges for all Child SAs.

4. **IKE Denial of Service / Exhaustion:**
   - Flooding gateways with half-open IKE_SA_INIT requests to consume memory and compute (cookie challenge defense).
   - *Defense:* Monitor half-open IKE exchanges and negotiation rates.

---

## 🔍 Limitations of Passive PCAP Analysis

- In ESP-only captures where IKE negotiation was not captured, internal configuration choices (such as exact cipher or PFS parameters) cannot always be established directly from packet headers.
- Accurate validation under these circumstances requires pairing PCAP analysis with VPN gateway configuration auditing (`swanctl.conf`).
