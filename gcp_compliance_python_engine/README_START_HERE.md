# 🎯 GCP Compliance Engine - START HERE

## Quick Start

### For Cursor AI (Recommended)

```
"Open MASTER_VALIDATION_ORCHESTRATOR.md and validate all 47 GCP services.
Update SERVICE_TRACKER_VALIDATOR.md as you complete each service."
```

### For Manual Validation

```bash
cd /Users/apple/Desktop/threat-engine/gcp_compliance_python_engine

# Validate all services
./validate_all_services.sh

# Validate specific service
export GCP_ENGINE_FILTER_SERVICES="compute"
python engine/gcp_engine.py > output/test.json 2>&1
```

---

## 📂 Essential Files Only

### 1. Main Workflow
- **MASTER_VALIDATION_ORCHESTRATOR.md** ← Start here with Cursor AI
- **SERVICE_TRACKER_VALIDATOR.md** ← Track progress (47 services)

### 2. Templates & Reference
- **GCP_YAML_INLINE_PROMPT.yaml** ← Template for service YAMLs
- **docs/YAML_ACTION_PATTERNS.md** ← Action pattern reference

### 3. Service Files
- **services/*/\*_rules.yaml** ← Each has inline validation prompt

### 4. Tools
- **validate_all_services.sh** ← Run automated validation
- **update_inline_prompts.py** ← Update YAML prompts (already run)

---

## 🎯 Mission

Validate all 47 services so the engine runs cleanly.

**Current Status:** Run `./validate_all_services.sh` to check

**Target:** 47/47 services ✅ VALIDATED

---

## 🤖 Best AI Model for This Task

### Recommended: **Claude Sonnet 3.5** (Default)
- ✅ Best for systematic validation tasks
- ✅ Good at following structured workflows
- ✅ Handles YAML and Python well
- ⚠️ May hit context limits on very long sessions

### Alternative: **GPT-4o** (For long sessions)
- ✅ Larger context window
- ✅ Good for multi-service batch processing
- ⚠️ May need more specific instructions

### For This Specific Task:
**Use Claude Sonnet 3.5** and work in batches:
- Validate 5-10 services per session
- Update tracker after each batch
- Start new session for next batch

---

## 💡 Tips to Avoid Token Issues

1. **Work in batches** - Don't try to do all 47 services in one session
2. **Update tracker frequently** - Save progress
3. **Start fresh sessions** - Every 10 services
4. **Use specific instructions** - "Validate services 1-10" vs "validate all"
5. **Focus on one service at a time** - Complete before moving on

---

## 🚀 Next Action

```
Open: MASTER_VALIDATION_ORCHESTRATOR.md
Task: Validate services in batches of 10
```

Good luck! 🎯

