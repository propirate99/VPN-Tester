# Testing Strategy & Test Scenarios

## Test Suite Overview

Automated tests in `tests/` validate that the analyzer handles valid, weak, failure, and corrupt captures properly:

### 1. Test Scenarios (Day 29 Matrix)

| Test ID | Scenario | Input Type | Expected Outcome |
|---|---|---|---|
| **Test 1** | Normal VPN | Valid IKEv2 + ESP with AES256, active PFS | `LOW` Risk Score (<= 30) |
| **Test 2** | Weak Configuration | Disabled PFS, weak crypto, duplicate ESP seq | `HIGH` / `CRITICAL` Risk Score (>= 61) |
| **Test 3** | Repeated IKE Failures | IKE_SA_INIT packets without IKE_AUTH | `MEDIUM` / `HIGH` Risk Score |
| **Test 4** | Anomalous Traffic | Packet rate spike, extreme packet counts | `ANOMALY DETECTED` |
| **Test 5** | Corrupt/Bad PCAP | Truncated or invalid PCAP binary | Graceful Error Handling (`ValueError`) |

---

## Running Automated Tests

```bash
# Run all unit and integration tests
pytest -v tests/

# Run with coverage report
pytest --cov=analyzer --cov=security tests/
```
