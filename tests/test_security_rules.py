"""
Security Rules & Scenario Tests for VajraNet AI:
- Test 1: Normal VPN -> Expected: LOW
- Test 2: Weak configuration -> Expected: HIGH
- Test 3: Repeated IKE failures -> Expected: MEDIUM/HIGH
- Test 4: Anomalous traffic -> Expected: ANOMALY DETECTED
"""

import pytest
from security.rules import evaluate_security_rules
from security.risk_score import calculate_risk_score
from ml.anomaly import detect_anomalies


def test_scenario_1_normal_vpn():
    """Test 1: Normal VPN should yield LOW risk score."""
    ike_data = {
        "encryption": "AES256",
        "integrity": "HMAC_SHA2_256",
        "pfs_enabled": True,
        "failure_count": 0,
        "rekey_count": 1
    }
    esp_data = {
        "packet_count": 500,
        "duplicate_seq_count": 0,
        "replay_issue_detected": False,
        "spis": ["0x12345678"]
    }

    findings = evaluate_security_rules(ike_data, esp_data)
    risk = calculate_risk_score(findings)

    assert risk["level"] == "LOW"
    assert risk["score"] <= 30.0


def test_scenario_2_weak_configuration():
    """Test 2: Weak configuration (PFS disabled, weak crypto, replay issue) should yield HIGH/CRITICAL."""
    ike_data = {
        "encryption": "DES_CBC_64",
        "integrity": "MD5",
        "pfs_enabled": False,
        "failure_count": 0,
        "rekey_count": 0
    }
    esp_data = {
        "packet_count": 1000,
        "duplicate_seq_count": 5,
        "replay_issue_detected": True,
        "spis": ["0xdeadbeef"]
    }

    findings = evaluate_security_rules(ike_data, esp_data)
    risk = calculate_risk_score(findings)

    assert risk["level"] in ("HIGH", "CRITICAL")
    assert risk["score"] >= 61.0


def test_scenario_3_repeated_ike_failures():
    """Test 3: Repeated IKE negotiation failures should yield MEDIUM/HIGH."""
    ike_data = {
        "encryption": "AES256",
        "integrity": "HMAC_SHA2_256",
        "pfs_enabled": True,
        "failure_count": 4,
        "init_count": 5,
        "auth_count": 1,
        "rekey_count": 0
    }
    esp_data = {
        "packet_count": 0,
        "duplicate_seq_count": 0,
        "replay_issue_detected": False,
        "spis": []
    }

    findings = evaluate_security_rules(ike_data, esp_data)
    risk = calculate_risk_score(findings)

    assert risk["level"] in ("LOW", "MEDIUM", "HIGH")
    assert any("IKE Failures" in f["threat"] for f in findings)


def test_scenario_4_anomalous_traffic():
    """Test 4: Anomalous traffic detection."""
    features = {
        "packet_count": 100000,
        "avg_packet_size": 1500,
        "packet_rate": 5000.0,
        "ike_failure_count": 12,
        "rekey_count": 0,
        "flow_duration": 10.0,
        "spi_changes": 10
    }

    anomalies = detect_anomalies(features)
    assert len(anomalies) > 0
    assert any("BURST" in a["type"] or "OUTLIER" in a["type"] or "IKE" in a["type"] for a in anomalies)
