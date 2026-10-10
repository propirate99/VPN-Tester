# Privacy & Data Handling Policy

## 🛡️ Non-Decryption Guarantee

VajraNet AI is strictly designed to operate without breaking or intercepting payload encryption:
1. **No Payload Decryption:** The analyzer does not decrypt the contents of ESP packets. All assessments rely exclusively on packet headers, negotiation metadata, sequence numbers, and configuration policies.
2. **Authorized Data Only:** The system must only be used with authorized captures from controlled test environments or networks where explicit permission has been obtained.
3. **No Credential Harvesting:** Pre-shared keys, private keys, and authentication secrets are never extracted, stored, or required for passive assessment.

---

## 🔒 Data Retention & Handling

- Uploaded PCAPs are processed in isolated temporary workspaces.
- Assessment results stored in SQLite contain only metadata summaries, statistical features, and high-level findings.
- Raw network captures are not transmitted to external third-party services or cloud AI models.
