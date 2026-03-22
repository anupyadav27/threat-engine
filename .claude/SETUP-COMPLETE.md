# Claude Code Setup Complete ✓

## What Was Configured

### 1. Settings & Permissions (`.claude/settings.json`)
- ✓ Model: Sonnet (switchable to Opus/Haiku)
- ✓ Extended context enabled (1M tokens)
- ✓ Comprehensive permissions for Docker, Kubernetes, AWS, Git
- ✓ Security restrictions (no secrets access, no destructive commands)
- ✓ Sandbox filesystem restrictions

### 2. Project Context (`.claude/CLAUDE.md`)
- ✓ Complete project overview
- ✓ Architecture patterns and data flow
- ✓ Development commands and workflows
- ✓ Security guidelines and protected files
- ✓ Debugging and troubleshooting guides
- ✓ Absolute path requirements documented

### 3. MCP Servers (`.claude/mcp.json`)
- ✓ GitHub integration configured (ready for activation)
- Ready to add: AWS, Kubernetes, PostgreSQL MCP servers

### 4. Modular Rules
- ✓ `rules/kubernetes-operations.md` - EKS deployment standards
- ✓ `rules/database-operations.md` - SQL and schema guidelines
- ✓ `rules/python-standards.md` - Python code quality standards

### 5. Directory Structure
```
.claude/
├── CLAUDE.md                    # Main project context
├── SETUP-COMPLETE.md            # This file
├── settings.json                # Configuration
├── mcp.json                     # MCP server definitions
├── documentation/               # Ready for detailed docs
├── rules/                       # Code-specific standards
│   ├── kubernetes-operations.md
│   ├── database-operations.md
│   └── python-standards.md
└── examples/                    # Ready for code examples
```

---

## Next Steps

### Immediate Actions

#### 1. Activate Configuration
Restart Claude Code to load the new configuration:
```bash
# Exit current session
/exit

# Start fresh session (loads new config)
claude
```

#### 2. Install Recommended MCP Servers

**GitHub (already configured):**
```bash
# Activate GitHub MCP in session
/mcp
# Follow OAuth login flow in browser
```

**AWS Operations:**
```bash
claude mcp add --scope project --transport stdio aws \
  -- npx @modelcontextprotocol/server-aws
```

**Kubernetes:**
```bash
claude mcp add --scope project --transport stdio kubernetes \
  -- npx @modelcontextprotocol/server-kubernetes
```

**PostgreSQL:**
```bash
claude mcp add --scope project --transport stdio postgres \
  -- npx @modelcontextprotocol/server-postgres \
    --env DATABASE_URL="${DATABASE_URL}"
```

**Custom MCP for your RDS (optional):**
```bash
# Create .env file with database URL
echo "DATABASE_URL=postgresql://user:pass@postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432/threat_engine_discoveries" > .env

# Add MCP server
claude mcp add --scope project --transport stdio rds \
  -- npx @modelcontextprotocol/server-postgres \
    --env DATABASE_URL
```

#### 3. Verify MCP Installation
```bash
# List all configured MCP servers
claude mcp list

# Check status in Claude Code session
/mcp
```

### Optional Enhancements

#### 1. Create Detailed Documentation
Add comprehensive guides to `.claude/documentation/`:

**Architecture:**
```bash
# Create from existing docs or generate
touch .claude/documentation/ARCHITECTURE.md
touch .claude/documentation/DATABASE-SCHEMA.md
touch .claude/documentation/API-REFERENCE.md
touch .claude/documentation/DEPLOYMENT.md
touch .claude/documentation/TROUBLESHOOTING.md
```

**Import in CLAUDE.md:**
```markdown
See @.claude/documentation/ARCHITECTURE.md for system design
See @.claude/documentation/DATABASE-SCHEMA.md for data models
```

#### 2. Add Code Examples
Create working examples for common patterns:

```bash
touch .claude/examples/ONBOARDING.md
touch .claude/examples/DISCOVERY.md
touch .claude/examples/THREAT-DETECTION.md
touch .claude/examples/KUBERNETES-DEPLOYMENT.md
```

#### 3. Set Up Auto Memory
Enable Claude's automatic learning:
```bash
# Auto memory is enabled by default
# View memory index
cat ~/.claude/projects/threat-engine/memory/MEMORY.md

# Edit memory in session
/memory
```

#### 4. Configure Local Overrides
Create personal settings (not version controlled):
```bash
# Create local settings override
touch .claude/settings.local.json
```

Example `.claude/settings.local.json`:
```json
{
  "model": "Opus",
  "env": {
    "LOG_LEVEL": "DEBUG"
  }
}
```

#### 5. Add Project-Specific Commands (Slash Commands)
Create custom slash commands in `.claude/commands/`:

```bash
mkdir -p .claude/commands

# Create review command
echo "Review the current PR for security issues, code quality, and test coverage" > .claude/commands/review.md

# Create deploy command
echo "Deploy the current branch to EKS staging environment" > .claude/commands/deploy-staging.md
```

Usage in Claude Code:
```
/review
/deploy-staging
```

---

## Configuration Management

### Settings Hierarchy (Highest to Lowest Priority)

1. **Command-line arguments**: `claude --model opus`
2. **Local settings**: `.claude/settings.local.json` (personal, not committed)
3. **Project settings**: `.claude/settings.json` (shared, committed)
4. **User settings**: `~/.claude/settings.json` (cross-project)

### Version Control

**Commit to Git:**
- `.claude/settings.json` ✓
- `.claude/CLAUDE.md` ✓
- `.claude/mcp.json` ✓
- `.claude/rules/*.md` ✓
- `.claude/documentation/*.md` ✓
- `.claude/examples/*.md` ✓

**Add to .gitignore:**
```
.claude/settings.local.json
.claude/.memory/
```

---

## Testing Your Setup

### 1. Context Loading
Start Claude Code and verify context:
```
/context
```

Should show CLAUDE.md and rules loaded.

### 2. Model Switching
```
/model sonnet
/model opus[1m]
/model opusplan
```

### 3. MCP Server Status
```
/mcp
```

Should list all configured servers and their status.

### 4. Permission Testing
Try a command:
```
Can you show me git status?
```

Should execute without prompting (pre-approved).

Try a restricted command:
```
Can you run kubectl delete deployment engine-discoveries?
```

Should ask for confirmation (in "ask" list).

### 5. Rules Application
Edit a Python file and check if Claude follows:
- Type hints
- Docstrings
- Import organization
- Absolute paths

---

## Recommended Workflows

### Daily Development
```bash
# Start Claude Code
claude

# Check context
/context

# Review changes
What files have changed? (Claude runs git status)

# Work on feature
Help me implement <feature>

# Review before commit
Review my changes for security and quality

# Commit (Claude creates PR-ready commit message)
Create a commit for these changes
```

### Deployment Workflow
```bash
# Review deployment manifest
Review deployment/aws/eks/engines/engine-discoveries.yaml

# Build and push
Build and push the Docker image for engine-discoveries

# Deploy to staging
kubectl apply -f deployment/aws/eks/engines/engine-discoveries.yaml

# Monitor rollout
kubectl rollout status deployment/engine-discoveries -n threat-engine-engines
```

### Database Changes
```bash
# Create migration
Create a migration to add threat_intelligence table

# Review schema
Review consolidated_services/database/schemas/threat_schema.sql

# Test migration
python migrate.py --dry-run

# Apply migration
python migrate.py --apply
```

---

## Advanced Features

### Extended Context (1M tokens)
For very large codebases or complex analysis:
```
/model sonnet[1m]
/model opus[1m]
```

### Hybrid Approach (Best of Both)
Use Opus for planning, Sonnet for execution:
```
/model opusplan
```

### Tool Search (Automatic)
When MCP tools exceed 10% of context, tool search auto-activates.
Control with:
```bash
export ENABLE_TOOL_SEARCH=auto  # Default
export ENABLE_TOOL_SEARCH=true  # Always on
export ENABLE_TOOL_SEARCH=false # Always off
```

### Compact Context
When context gets full:
```
/compact keep recent code changes, summarize earlier discussions
```

### Clear Context
Between unrelated tasks:
```
/clear
```

---

## Security Notes

### Protected by Configuration
- ✗ Cannot read `.env` files
- ✗ Cannot read `/secrets/` directory
- ✗ Cannot run `rm -rf`, `curl`, `wget`, `sudo`
- ✗ Cannot edit deployment files without confirmation
- ✗ Cannot delete Kubernetes resources without confirmation

### Credential Management
- AWS credentials: Use IAM roles or Secrets Manager
- Database passwords: Store in AWS Secrets Manager
- API keys: Reference via environment variables
- Never commit secrets to Git

### Audit Trail
All Claude Code operations are logged. Review logs:
```bash
# View recent activity
tail -f ~/.claude/logs/session.log
```

---

## Troubleshooting

### MCP Server Not Working
```bash
# Check server status
/mcp

# Remove and re-add
claude mcp remove <server-name>
claude mcp add --scope project --transport http <server-name> <url>

# Check logs
cat ~/.claude/logs/mcp-<server-name>.log
```

### Context Not Loading
```bash
# Verify file exists
cat /Users/apple/Desktop/threat-engine/.claude/CLAUDE.md

# Check syntax
yamllint .claude/rules/*.md

# Restart Claude Code
/exit
claude
```

### Permissions Not Working
```bash
# Check settings
cat .claude/settings.json

# Verify permissions array syntax
# Restart session
/exit
claude
```

---

## Additional Resources

### Documentation
- [MCP Guide](https://code.claude.com/docs/en/mcp.md)
- [Settings Reference](https://code.claude.com/docs/en/settings.md)
- [Permissions](https://code.claude.com/docs/en/permissions.md)
- [Memory Management](https://code.claude.com/docs/en/memory.md)

### Community
- [Claude Code GitHub](https://github.com/anthropics/claude-code)
- [MCP Servers Registry](https://github.com/modelcontextprotocol/servers)

---

## Summary

Your Claude Code setup is complete and optimized for:
- ✓ Cloud security platform development
- ✓ Kubernetes/EKS operations
- ✓ PostgreSQL database management
- ✓ Multi-engine architecture
- ✓ Security-first development
- ✓ Team collaboration (version-controlled config)

**Next:** Restart Claude Code and start building!

```bash
claude
```
