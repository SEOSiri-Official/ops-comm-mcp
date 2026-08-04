# tests/test_ops_comm.py
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.main_server import (
    parse_sentry_error_stacktrace,
    format_linear_issue_payload,
    dispatch_slack_incident_alert,
    correlate_github_commit_culprit,
    calculate_incident_severity_score,
    generate_incident_postmortem_markdown,
    export_ops_parquet_buffer,
    sanitize_ops_payload,
    get_live_ops_throughput_metrics,
    get_ops_server_specifications
)


def test_1_parse_sentry():
    event = json.dumps({"event_id": "sentry_100", "culprit": "db_module", "exception": {"values": [{"type": "ValueError", "value": "Connection refused"}]}})
    res = json.loads(parse_sentry_error_stacktrace(event))
    assert res["status"] == "PARSED"
    assert res["culprit_module"] == "db_module"


def test_2_linear_payload():
    res = json.loads(format_linear_issue_payload("Fix DB Error", "High urgency issue", 1, "ENG"))
    assert res["status"] == "PAYLOAD_COMPILED"
    assert res["linear_issue_payload"]["teamKey"] == "ENG"


def test_3_slack_alert():
    res = json.loads(dispatch_slack_incident_alert("Database Timeout", "CRITICAL", "DB connection lost"))
    assert res["status"] == "PAYLOAD_GENERATED"


def test_4_github_correlate():
    commits = json.dumps([{"commit_hash": "a1b2c3d", "author": "dev", "message": "Updated DB pool"}])
    res = json.loads(correlate_github_commit_culprit("2026-08-04T12:00:00Z", commits))
    assert res["status"] == "CORRELATED"


def test_5_severity_calculator():
    res = json.loads(calculate_incident_severity_score(25, 100, True))
    assert res["status"] == "CALCULATED"
    assert res["severity_score"] >= 80.0


def test_6_postmortem_generator():
    res = json.loads(generate_incident_postmortem_markdown("INC-100", "Database overload", "Scaled pool size"))
    assert res["status"] == "GENERATED"
    assert "INC-100" in res["postmortem_markdown"]


def test_7_parquet_export():
    res = json.loads(export_ops_parquet_buffer(10))
    assert res["status"] == "PARQUET_BUFFER_GENERATED"


def test_8_sanitize_payload():
    res = json.loads(sanitize_ops_payload("Authorization: Bearer my_secret_token_123"))
    assert res["status"] == "SANITIZED"
    assert "my_secret_token_123" not in res["clean_input"]


def test_9_throughput_metrics():
    res = json.loads(get_live_ops_throughput_metrics())
    assert res["status"] == "HEALTHY"


def test_10_server_specs():
    res = json.loads(get_ops_server_specifications())
    assert res["total_tools"] == 10