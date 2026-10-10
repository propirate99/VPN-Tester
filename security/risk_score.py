"""
Risk Scoring Engine for VajraNet AI.
Calculates overall risk score (0-100) and risk level (LOW, MEDIUM, HIGH, CRITICAL),
and builds the Threat Matrix summary table.
"""

from typing import Dict, Any, List

SEVERITY_WEIGHTS = {
    "PFS Disabled": 25,
    "Replay Issue": 25,
    "Weak Crypto": 25,
    "IKE Failures": 15,
    "Policy Drift": 10
}


def calculate_risk_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate composite risk score based on findings:
    0–30:   LOW
    31–60:  MEDIUM
    61–80:  HIGH
    81–100: CRITICAL
    """
    total_score = 0.0
    threat_matrix = []

    for f in findings:
        threat_name = f.get("threat", "General Finding")
        severity = f.get("severity", "LOW")
        evidence = f.get("evidence", "Not provided")
        recommendation = f.get("recommendation", "Review policy")

        # Add weighted score
        weight = SEVERITY_WEIGHTS.get(threat_name, 10)
        total_score += weight

        threat_matrix.append({
            "Threat": threat_name,
            "Severity": severity,
            "Evidence": evidence,
            "Recommendation": recommendation
        })

    # Clamp at 100
    final_score = min(100.0, float(total_score))

    if final_score <= 30.0:
        level = "LOW"
    elif final_score <= 60.0:
        level = "MEDIUM"
    elif final_score <= 80.0:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "score": final_score,
        "level": level,
        "threat_matrix": threat_matrix
    }
