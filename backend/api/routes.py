"""
FastAPI router definition with endpoints for PCAP upload, analysis, anomaly detection, and reports.
"""

import os
import shutil
from typing import Dict, Any, List
from fastapi import APIRouter, UploadFile, File, HTTPException

from analyzer.pcap_reader import read_pcap
from analyzer.ike_analyzer import analyze_ike_packets
from analyzer.esp_analyzer import analyze_esp_packets
from analyzer.feature_extractor import extract_vpn_features
from analyzer.timeline import build_sa_timeline
from security.rules import evaluate_security_rules
from security.risk_score import calculate_risk_score
from ml.anomaly import detect_anomalies
from backend.database.db import save_assessment, get_assessments, get_assessment_by_id

router = APIRouter()

UPLOAD_DIR = "/tmp/vajranet_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint to verify backend service status."""
    return {"status": "ok", "service": "VajraNet AI API"}


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Upload a PCAP or PCAPNG capture file."""
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file extension. Please upload a .pcap or .pcapng file.")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "status": "success",
        "filename": file.filename,
        "saved_path": file_path
    }


@router.post("/analyze")
async def analyze_capture(file: UploadFile = File(...)) -> Dict[str, Any]:
    """Upload and run end-to-end VPN security analysis on a PCAP file."""
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Invalid file format.")

    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        # 1. Read PCAP
        pcap_data = read_pcap(file_path)

        # 2. Protocol Analysis
        ike_data = analyze_ike_packets(pcap_data.get("packets", []))
        esp_data = analyze_esp_packets(pcap_data.get("packets", []))

        # 3. Features & Timeline
        features = extract_vpn_features(pcap_data, ike_data, esp_data)
        timeline = build_sa_timeline(ike_data.get("ike_events", []))

        # 4. Security Rules & Risk Calculation
        findings = evaluate_security_rules(ike_data, esp_data)
        risk_result = calculate_risk_score(findings)

        # 5. ML Anomaly Detection
        anomalies = detect_anomalies(features)

        tunnel_info = {
            "ike_version": ike_data.get("ike_version", "IKEv2"),
            "endpoints": pcap_data.get("endpoints", []),
            "spis": esp_data.get("spis", []),
            "encryption_algorithm": ike_data.get("encryption", "Unknown"),
            "integrity_algorithm": ike_data.get("integrity", "Unknown"),
            "tunnel_status": "ACTIVE" if esp_data.get("packet_count", 0) > 0 else "INACTIVE"
        }

        # 6. Save Assessment
        record_id = save_assessment(
            filename=file.filename,
            packet_count=pcap_data.get("total_packets", 0),
            risk_score=risk_result["score"],
            risk_level=risk_result["level"],
            tunnel_info=tunnel_info,
            findings=findings,
            timeline=timeline,
            anomalies=anomalies
        )

        return {
            "id": record_id,
            "filename": file.filename,
            "packet_count": pcap_data.get("total_packets", 0),
            "duration": pcap_data.get("duration", 0),
            "tunnel_info": tunnel_info,
            "risk_score": risk_result["score"],
            "risk_level": risk_result["level"],
            "findings": findings,
            "threat_matrix": risk_result["threat_matrix"],
            "timeline": timeline,
            "anomalies": anomalies,
            "features": features
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/anomaly")
def anomaly_check(features: Dict[str, Any]) -> Dict[str, Any]:
    """Run anomaly detection scoring directly on extracted feature metrics."""
    return {"anomalies": detect_anomalies(features)}


@router.get("/assessments")
def list_assessments() -> List[Dict[str, Any]]:
    """List historical assessment summaries."""
    return get_assessments()


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: int) -> Dict[str, Any]:
    """Retrieve details for a specific assessment."""
    assessment = get_assessment_by_id(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment
