# Claude Code Quick Reference

## Essential Commands

### Session Management
```
/help              - Get help
/context           - View context usage
/clear             - Reset context
/compact <focus>   - Selective summarization
/memory            - Edit memory files
/exit              - End session
```

### Model Switching
```
/model             - Show current model
/model sonnet      - Switch to Sonnet (balanced)
/model opus        - Switch to Opus (complex reasoning)
/model haiku       - Switch to Haiku (fast, simple)
/model sonnet[1m]  - Extended context (1M tokens)
/model opusplan    - Hybrid: Opus planning, Sonnet execution
```

### MCP Management
```
/mcp               - Check MCP server status
claude mcp list    - List all MCP servers (terminal)
claude mcp add     - Add MCP server (terminal)
claude mcp remove  - Remove MCP server (terminal)
```

### Git Operations (Ask Claude)
```
"Show me git status"
"Create a commit for these changes"
"Review my changes before committing"
"What files have been modified?"
```

## Common Prompts

### Development
```
"Help me implement <feature>"
"Review this code for security issues"
"Explain how <component> works"
"Debug why <issue> is happening"
"Refactor <function> to be more efficient"
```

### Kubernetes
```
"Show me the status of all deployments"
"Check logs for engine-discoveries pod"
"Apply the updated manifest for <engine>"
"Port forward engine-compliance to local port 8000"
```

### Database
```
"Create a migration to add <table>"
"Review the discovery_findings schema"
"Explain the data flow from discovery to threat engine"
```

### Documentation
```
"Document the API endpoints for <engine>"
"Create examples for <workflow>"
"Update CLAUDE.md with new architecture changes"
```

## Absolute Paths (Always Use These)

```
Base:     /Users/apple/Desktop/threat-engine/

Schemas:  /Users/apple/Desktop/threat-engine/consolidated_services/database/schemas/
Config:   /Users/apple/Desktop/threat-engine/consolidated_services/database/config/
Engines:  /Users/apple/Desktop/threat-engine/engine_*/
K8s:      /Users/apple/Desktop/threat-engine/deployment/aws/eks/
Docker:   /Users/apple/Desktop/threat-engine/deployment/docker/
```

## File Structure

```
threat-engine/
├── .claude/
│   ├── CLAUDE.md              - Main project context
│   ├── settings.json          - Configuration
│   ├── mcp.json              - MCP servers
│   ├── SETUP-COMPLETE.md     - Setup guide
│   ├── QUICK-REFERENCE.md    - This file
│   ├── documentation/        - Detailed docs
│   ├── rules/                - Code standards
│   │   ├── kubernetes-operations.md
│   │   ├── database-operations.md
│   │   └── python-standards.md
│   └── examples/             - Code examples
├── engine_*/                  - Individual engines
├── consolidated_services/     - Shared database/services
├── deployment/               - K8s & Docker configs
└── Vulnerability-main/       - Vuln subsystem
```

## Pre-Approved Commands

These run without confirmation:
- `git status`, `git log`, `git diff`, `git branch`
- `docker build`, `docker run`, `docker logs`, `docker ps`
- `kubectl get`, `kubectl describe`, `kubectl logs`
- `pytest`, `python`, `pip`
- File reads anywhere in project
- File edits in `engine_*/`, `src/**`, `tests/**`

## Requires Confirmation

These ask before running:
- `kubectl delete`
- `docker push`
- Editing `deployment/aws/eks/**`

## Blocked (Cannot Run)

- `rm -rf`
- `curl`, `wget`
- `sudo`
- Reading `.env` files
- Reading `/secrets/` directory
- Editing `.git/` directory

## Workflow Examples

### Feature Development
1. "Show me git status"
2. "Create a feature branch called feature/xyz"
3. "Help me implement <feature>"
4. "Run tests to verify changes"
5. "Review my changes for quality and security"
6. "Create a commit with descriptive message"

### Deployment
1. "Review the deployment manifest for <engine>"
2. "Build Docker image for <engine>"
3. "Push image to Docker Hub" (asks confirmation)
4. "Apply K8s manifest to staging"
5. "Check rollout status"
6. "Monitor pod logs"

### Database Changes
1. "Create migration for <change>"
2. "Review the migration SQL"
3. "Test migration with dry-run"
4. "Apply migration to database"
5. "Verify schema changes"

## Tips & Best Practices

### Context Management
- Check context: `/context`
- Low on space? `/compact keep recent work, summarize earlier`
- Switching tasks? `/clear` to start fresh
- Complex analysis? `/model opus[1m]` for extended context

### Effective Prompts
- Be specific: "Add JSONB column to threat_findings table" vs "update database"
- Provide context: "In engine_discoveries, add retry logic for rate limits"
- Ask for review: "Review this for security issues before committing"

### File Operations
- Always use absolute paths in bash commands
- Reference files: "Edit /Users/apple/Desktop/threat-engine/engine_discoveries/api_server.py"
- Multiple files: "Review files in engine_threat/"

### Debugging
- Start broad: "Show me the logs for engine-compliance"
- Narrow down: "Filter logs for errors in the last hour"
- Root cause: "Explain why this error is occurring"

## MCP Servers to Install

### GitHub (configured, needs activation)
```bash
/mcp  # In Claude Code session, follow OAuth flow
```

### AWS
```bash
claude mcp add --scope project --transport stdio aws \
  -- npx @modelcontextprotocol/server-aws
```

### Kubernetes
```bash
claude mcp add --scope project --transport stdio kubernetes \
  -- npx @modelcontextprotocol/server-kubernetes
```

### PostgreSQL (RDS)
```bash
claude mcp add --scope project --transport stdio postgres \
  -- npx @modelcontextprotocol/server-postgres \
    --env DATABASE_URL="${DATABASE_URL}"
```

## Keyboard Shortcuts (Terminal)

```
Ctrl+C    - Interrupt current operation
Ctrl+D    - Exit session
Tab       - Autocomplete (some terminals)
↑/↓       - Command history
```

## Getting Help

### In Session
```
/help
"How do I <task>?"
"What's the best way to <goal>?"
```

### Documentation
- Project context: `.claude/CLAUDE.md`
- Setup guide: `.claude/SETUP-COMPLETE.md`
- Code standards: `.claude/rules/`

### Troubleshooting
1. Restart session: `/exit` then `claude`
2. Check settings: `cat .claude/settings.json`
3. Verify MCP: `/mcp`
4. Review logs: `tail -f ~/.claude/logs/session.log`

## Quick Diagnostics

### Is Claude Code working?
```
"Show me git status"  # Should run without error
```

### Are permissions configured?
```
"Run kubectl get pods"  # Should run without prompt
"Delete this deployment"  # Should ask for confirmation
```

### Is MCP working?
```
/mcp  # Should list configured servers
```

### Is context loading?
```
/context  # Should show CLAUDE.md loaded
```

---

**Remember:** Claude Code learns and improves with auto memory. The more you work, the better it understands your project!
