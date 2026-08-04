# seosiri-ops-comm-mcp

> 📖 **Official Architecture & Documentation:** [SEOSiri Operations & Incident Response Guide](https://www.seosiri.com/2026/08/ops-comm-mcp.html) | [Central MCP Directory](https://www.seosiri.com/2026/07/seosiri-mcp-servers.html)

An open-source, local-first Model Context Protocol (MCP) server for **Enterprise Operations, Sentry Error Triage, Linear Issue Sync, and Slack Incident Response**.

## 💖 Sponsorship, B2B Custom Solutions & Attribution

### 👨‍💻 Lead Architect & Attribution
Designed and engineered by **[Momenul Ahmad](https://github.com/MOBILEPHONE)**, Lead Architect and Founder of **[SEOSiri](https://seosiri.com)**.

### 🚀 Capabilities & Tools (10 Production Tools)
- **`parse_sentry_error_stacktrace`**: Parses raw Sentry exception payloads and extracts stacktraces.
- **`format_linear_issue_payload`**: Compiles structured Linear issue payloads with priority tags.
- **`dispatch_slack_incident_alert`**: Formats and dispatches Slack Block Kit JSON payloads to operational channels.
- **`correlate_github_commit_culprit`**: Matches Sentry error timestamps against GitHub commit histories.
- **`calculate_incident_severity_score`**: Computes algorithmic incident severity scores ($0\text{--}100$).
- **`generate_incident_postmortem_markdown`**: Compiles Blameless Postmortem Markdown reports.
- **`export_ops_parquet_buffer`**: Formats incident logs into columnar Parquet buffers for DuckDB/S3.
- **`sanitize_ops_payload`**: Strips API tokens and passwords from error logs.
- **`get_live_ops_throughput_metrics`**: Monitors system health and processing latency.
- **`get_ops_server_specifications`**: Returns protocol specs and capability matrices.

## Quickstart

```bash
# Install package in editable mode
pip install -e .

# Run test suite
pytest tests/test_ops_comm.py
```

## 🔌 Claude Desktop / Cursor Configuration

Add this block to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "seosiri-ops-comm": {
      "command": "uv",
      "args": [
        "run",
        "--github",
        "SEOSiri-Official/ops-comm-mcp",
        "src/main_server.py"
      ]
    }
  }
}
```

## 📄 License

Distributed under the MIT License. See the official [LICENSE](https://github.com/SEOSiri-Official/ops-comm-mcp/blob/main/LICENSE) file for more details.
