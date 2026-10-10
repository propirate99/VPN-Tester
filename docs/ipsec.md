# IPsec & IKEv2 Protocols Guide

## 1. What is IPsec?

Internet Protocol Security (IPsec) is a suite of protocols designed to secure IP communications by authenticating and encrypting each IP packet in a session.

### Core Protocols
- **IKE (Internet Key Exchange - IKEv2):** Used to authenticate peers, exchange keying material, and negotiate Security Associations (SAs). Operates over UDP port 500 (or UDP port 4500 when NAT Traversal is active).
- **ESP (Encapsulating Security Payload):** Provides confidentiality, data origin authentication, data integrity, and anti-replay protection. Operates as IP Protocol 50.
- **AH (Authentication Header):** Provides integrity and authentication without confidentiality (rarely used in modern deployments; ESP with NULL encryption preferred).

---

## 2. Modes of Operation

1. **Tunnel Mode:** The entire original IP packet is encrypted and encapsulated within a new outer IP header. Typically used for gateway-to-gateway (site-to-site) VPNs.
2. **Transport Mode:** Only the IP payload is encrypted; original IP header is preserved. Used for host-to-host communications.

---

## 3. IKEv2 Exchange Flow

```text
Initiator                                           Responder
    |                                                   |
    |---- IKE_SA_INIT (HDR, SAi1, KEi, Ni) ------------>|
    |<--- IKE_SA_INIT (HDR, SAr1, KEr, Nr, [CERTREQ]) --|
    |                                                   |
    |---- IKE_AUTH (HDR, SK {IDi, [CERT,] AUTH, SA2}) ->|
    |<--- IKE_AUTH (HDR, SK {IDr, [CERT,] AUTH, SA2}) --|
    |                                                   |
    |================= CHILD_SA Established ============|
    |                                                   |
    |<--- ESP Encrypted Payload Traffic (Proto 50) ---->|
```

- **IKE_SA_INIT:** Negotiates cryptographic algorithms for the IKE SA, exchanges nonces, and performs Diffie-Hellman exchange.
- **IKE_AUTH:** Authenticates peers and creates the first CHILD_SA (ESP SA).
- **CREATE_CHILD_SA:** Establishes additional SAs or performs SA rekeying.

---

## 4. Security Associations (SAs) & SPI

A **Security Association (SA)** is a simplex (unidirectional) logical connection providing security services to the traffic carried over it.
- Identified by a 32-bit **Security Parameter Index (SPI)**, destination IP address, and security protocol (ESP).
- Bidirectional communication requires two SAs (one in each direction).
