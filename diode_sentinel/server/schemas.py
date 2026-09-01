"""
DiodeSentinel - API Schemas & Standardized Alert Data Contracts
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class AlertEvidence(BaseModel):
    """Structured forensic evidence supporting the ML/heuristic detection."""
    detection_logic: str = Field(description="Human readable explanation of why the rule or ML model fired")
    metrics: Dict[str, Any] = Field(default_factory=dict, description="Raw mathematical/statistical indicators")


class AlertRecord(BaseModel):
    """Standardized Security Alert Schema for Unidirectional Diode Enclave."""
    timestamp: str = Field(description="ISO-8601 UTC timestamp of detection")
    alert_id: str = Field(description="Unique Alert Identifier")
    flow_id: str = Field(description="Flow 5-tuple identifier")
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    threat_class: str = Field(description="One of 6 standard threat classes")
    subtype: str
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Model confidence score")
    mitre_technique: str = Field(description="Associated MITRE ATT&CK technique and ID")
    summary: str = Field(description="Executive triage summary")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Forensic evidence features")
    flow_snapshot: Dict[str, Any] = Field(default_factory=dict, description="Snapshot of flow metrics at trigger time")


class AttackInjectionRequest(BaseModel):
    """Request payload to inject a simulated cyber attack scenario into the stream."""
    attack_name: str
    params: Optional[Dict[str, Any]] = None


class SystemStatusResponse(BaseModel):
    """Real-time system health and throughput response."""
    status: str
    uptime_sec: float
    total_packets: int
    total_bytes: int
    active_flows_count: int
    current_pps: float
    current_mbps: float
    current_fps: float
    total_alerts: int
    threat_counts: Dict[str, int]
