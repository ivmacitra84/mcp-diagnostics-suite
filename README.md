# MCP Diagnostics Suite

Production-grade diagnostics MCP server. Provides structured host diagnostics,
environment introspection, and findings archival over the Model Context Protocol.

## Installation

npm install -g mcp-diagnostics-suite

## MCP Client Configuration

Add to your MCP client config:

```json
{
  "mcpServers": {
    "diagnostics": {
      "command": "npx",
      "args": ["-y", "mcp-diagnostics-suite"]
    }
  }
}
```

## Tools

- run_triage: collects structured host diagnostics
- get_env_context: summarizes the runtime environment
- summarize_findings: archives review findings
