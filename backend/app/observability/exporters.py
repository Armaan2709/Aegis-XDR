"""
Prometheus Text-Format Metrics Exporter for AegisAI XDR.
"""

from typing import Dict, Any


def generate_prometheus_metrics(metrics_data: Dict[str, Any]) -> str:
    """
    Format operational analytics metrics as standard Prometheus text metrics.

    Exposes:
    - aegis_alerts_total
    - aegis_incidents_total
    - aegis_active_investigations
    - aegis_pending_approvals
    - aegis_iocs_total
    - aegis_detection_rules_total
    - aegis_active_playbooks
    - aegis_mttd_seconds
    - aegis_mttr_seconds
    - aegis_agent_executions_total
    """
    platform = metrics_data.get("platform", {})
    soc = metrics_data.get("soc", {})
    pipeline = metrics_data.get("pipeline", {})
    agents = metrics_data.get("agents", {})

    lines = [
        "# HELP aegis_alerts_total Total count of security alerts ingested.",
        "# TYPE aegis_alerts_total counter",
        f"aegis_alerts_total {platform.get('total_alerts', 0)}",
        "",
        "# HELP aegis_incidents_total Total count of correlated incidents.",
        "# TYPE aegis_incidents_total counter",
        f"aegis_incidents_total {platform.get('open_incidents', 0)}",
        "",
        "# HELP aegis_active_investigations Number of active investigation sessions.",
        "# TYPE aegis_active_investigations gauge",
        f"aegis_active_investigations {platform.get('active_investigations', 0)}",
        "",
        "# HELP aegis_pending_approvals Number of pending human governance approvals.",
        "# TYPE aegis_pending_approvals gauge",
        f"aegis_pending_approvals {platform.get('pending_approvals', 0)}",
        "",
        "# HELP aegis_iocs_total Total threat intelligence indicators stored.",
        "# TYPE aegis_iocs_total gauge",
        f"aegis_iocs_total {platform.get('total_iocs', 0)}",
        f"aegis_iocs_malicious {platform.get('malicious_iocs', 0)}",
        "",
        "# HELP aegis_mttd_seconds Mean Time To Detect in seconds.",
        "# TYPE aegis_mttd_seconds gauge",
        f"aegis_mttd_seconds {soc.get('mttd_seconds') or 0.0}",
        "",
        "# HELP aegis_mttr_seconds Mean Time To Respond in seconds.",
        "# TYPE aegis_mttr_seconds gauge",
        f"aegis_mttr_seconds {soc.get('mttr_seconds') or 0.0}",
        "",
        "# HELP aegis_pipeline_executions_total Total autonomous pipeline runs.",
        "# TYPE aegis_pipeline_executions_total counter",
        f"aegis_pipeline_executions_total {pipeline.get('total_executions', 0)}",
        f"aegis_pipeline_failures_total {pipeline.get('failed_executions', 0)}",
        "",
        "# HELP aegis_agent_executions_total Aggregated AI agent executions.",
        "# TYPE aegis_agent_executions_total counter",
        f"aegis_agent_executions_total {agents.get('total_agent_runs', 0)}",
        f"aegis_agent_overall_success_rate {agents.get('overall_success_rate', 100.0)}",
    ]

    # Individual Agent Metrics
    for ag in agents.get("agents", []):
        agent_name = ag.get("agent_name", "unknown").replace(" ", "_").lower()
        lines.append(f'aegis_agent_runs_total{{agent="{agent_name}"}} {ag.get("execution_count", 0)}')
        lines.append(f'aegis_agent_success_rate{{agent="{agent_name}"}} {ag.get("success_rate", 100.0)}')

    return "\n".join(lines) + "\n"
