"""
Security Rules Engine for VajraNet AI.
Evaluates configuration and traffic against the security baseline policy (PFS, Replay, Crypto, SA Lifetime, IKE Failures).
Outputs findings adhering to the finding format: severity, finding, evidence, recommendation.
"""

import os
import yaml
from typing import Dict, Any, List

POLICY_FILE = os.path.join(os.path.dirname(__file__), "policy.yaml")


def load_policy() -> Dict[str, Any]:
    """Load policy configuration from policy.yaml."""
    if os.path.exists(POLICY_FILE):
        with open(POLICY_FILE, "r") as f:
            data = yaml.safe_load(f)
            return data.get("policy", {})
    return {
        "pfs": True,
        "replay_protection": True,
        "max_sa_lifetime": 3600,
        "allowed_algorithms": ["AES256"]
    }


def check_pfs(ike_data: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verify Perfect Forward Secrecy (PFS) enforcement."""
    findings = []
    required_pfs = policy.get("pfs", True)
    is_pfs = ike_data.get("pfs_enabled", True)

    if required_pfs and not is_pfs:
        findings.append({
            "threat": "PFS Disabled",
            "severity": "HIGH",
            "finding": "Perfect Forward Secrecy (PFS) is disabled or not negotiated for Child SAs.",
            "evidence": "Observed CREATE_CHILD_SA exchanges lack Diffie-Hellman KE payloads.",
            "recommendation": "Enable PFS in strongSwan/VPN gateway policy configuration."
        })
    return findings


def check_replay_protection(esp_data: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verify Anti-Replay protection and sequence number continuity."""
    findings = []
    dup_count = esp_data.get("duplicate_seq_count", 0)

    if dup_count > 0:
        findings.append({
            "threat": "Replay Issue",
            "severity": "HIGH",
            "finding": f"Possible replay attack or sequence number duplication detected ({dup_count} duplicates).",
            "evidence": f"ESP sequence numbers duplicated across SPIs: {esp_data.get('spis')}.",
            "recommendation": "Verify anti-replay window is active and check network for duplicate/replayed frames."
        })
    return findings


def check_crypto(ike_data: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Validate encryption and integrity algorithms against approved cipher list."""
    findings = []
    allowed = policy.get("allowed_algorithms", ["AES256"])
    encryption = ike_data.get("encryption", "")

    # Check if encryption matches approved baseline
    is_allowed = any(a.lower() in encryption.lower() for a in allowed)
    if encryption and not is_allowed:
        findings.append({
            "threat": "Weak Crypto",
            "severity": "HIGH",
            "finding": f"Disallowed or weak encryption suite in use: {encryption}.",
            "evidence": f"IKE SA proposal negotiated {encryption}, expected one of {allowed}.",
            "recommendation": "Upgrade IKE and ESP proposal to approved cryptographic algorithms (e.g. AES256-GCM)."
        })
    return findings


def check_ike_failures(ike_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for repeated IKE negotiation and authentication failures."""
    findings = []
    failures = ike_data.get("failure_count", 0)
    init_count = ike_data.get("init_count", 0)

    if failures >= 3:
        findings.append({
            "threat": "IKE Failures",
            "severity": "HIGH" if failures > 5 else "MEDIUM",
            "finding": f"Repeated IKE negotiation failures detected ({failures} unacknowledged attempts).",
            "evidence": f"Observed {init_count} IKE_SA_INIT with missing or rejected IKE_AUTH completions.",
            "recommendation": "Check PSK/certificates, peer reachability, and proposal compatibility on both endpoints."
        })
    return findings


def check_sa_lifetime(ike_data: Dict[str, Any], esp_data: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Verify SA rekeying interval and lifetime safety."""
    findings = []
    rekey_count = ike_data.get("rekey_count", 0)
    esp_count = esp_data.get("packet_count", 0)

    # Flag if high volume of ESP without any rekeys observed
    if esp_count > 10000 and rekey_count == 0:
        findings.append({
            "threat": "Policy Drift",
            "severity": "LOW",
            "finding": "High volume ESP traffic observed without rekeying event in capture window.",
            "evidence": f"{esp_count} ESP packets recorded under a single Security Association.",
            "recommendation": "Ensure volume-based and time-based SA rekeying limits are configured."
        })
    return findings


def evaluate_security_rules(ike_data: Dict[str, Any], esp_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Run all security checks against parsed protocol state."""
    policy = load_policy()
    findings = []

    findings.extend(check_pfs(ike_data, policy))
    findings.extend(check_replay_protection(esp_data, policy))
    findings.extend(check_crypto(ike_data, policy))
    findings.extend(check_ike_failures(ike_data))
    findings.extend(check_sa_lifetime(ike_data, esp_data, policy))

    return findings
