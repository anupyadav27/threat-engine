# Monitor Sequential Run Progress

## Process Running

**PID**: Check with `ps aux | grep run_sequential_all`  
**Started**: Check `sequential_run.log` for timestamp  
**Prevents sleep**: Using `caffeinate` - system will NOT sleep during run

## How to Monitor

### Watch live progress:
```bash
cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/Agent-rulesid-rule-yaml

tail -f sequential_run.log
```

Press `Ctrl+C` to stop watching (process continues in background)

### Check last 50 lines:
```bash
tail -50 sequential_run.log
```

### Search for specific service:
```bash
grep "accessanalyzer" sequential_run.log
grep "Processing service:" sequential_run.log | tail -10
```

### Check if still running:
```bash
ps aux | grep run_sequential_all
```

### Check current progress (count completed services):
```bash
grep "Processing service:" sequential_run.log | wc -l
```

## Files Being Created

### During run:
```bash
ls -lh output/
```

You should see:
- `requirements_initial.json` (grows as services processed)
- `requirements_with_functions.json` (Agent 2 output)
- `requirements_validated.json` (Agent 3 output)
- `*.yaml` files (Agent 4 output)

### Check size growing:
```bash
watch -n 10 'ls -lh output/*.json'
```

### Count rules so far:
```bash
python3 << 'EOF'
import json
try:
    with open('output/requirements_validated.json') as f:
        data = json.load(f)
    services = len(data)
    total = sum(len(rules) for rules in data.values())
    validated = sum(1 for svc in data.values() for r in svc if r.get('all_fields_valid'))
    print(f"Services: {services}/101")
    print(f"Rules: {total}")
    print(f"Validated: {validated} ({validated/total*100:.1f}%)" if total > 0 else "")
except:
    print("Not ready yet or still processing...")
EOF
```

## Expected Timeline

Based on 101 services:

- **Agent 1** (AI generation): 30-60 seconds per service = 50-100 min
- **Agent 2** (function validation): Fast, ~10-20 min total
- **Agent 3** (field validation): Fast, ~10-20 min total  
- **Agent 4** (YAML generation): Fast, ~5-10 min total

**Total**: 1-2 hours

## Progress Indicators

Look for these in the log:

```
Processing service: accessanalyzer
  Found 2 metadata files
  Generating requirements...
  ✅ 2 requirements generated

Processing service: acm
  Found 5 metadata files
  Generating requirements...
  ✅ 5 requirements generated
```

## What Each Agent Does

```
Agent 1: [CURRENTLY RUNNING - SLOWEST]
  → Reads metadata YAMLs
  → Calls GPT-4o for each rule
  → Generates requirements_initial.json

Agent 2: [WILL START AFTER AGENT 1]
  → Validates boto3 function names
  → Fast processing

Agent 3: [AFTER AGENT 2]
  → Validates field names
  → Fast processing

Agent 4: [FINAL STEP]
  → Generates YAML files
  → Fast processing
```

## If Something Goes Wrong

### Check for errors:
```bash
grep -i "error" sequential_run.log
grep -i "failed" sequential_run.log
grep "❌" sequential_run.log
```

### Stop the process:
```bash
# Find PID
ps aux | grep run_sequential_all

# Kill it
kill <PID>

# Or kill all related
pkill -f run_sequential_all
pkill -f caffeinate  # Re-enable sleep
```

### Resume from failure:
The current setup doesn't support resume. You'd need to:
1. Check which services completed
2. Edit agent1 SERVICES_TO_PROCESS to remove completed ones
3. Run again

## When Complete

You'll see in the log:
```
========================================
✅ SEQUENTIAL PIPELINE COMPLETE
========================================

Duration: XXm XXs

Results:
  Services processed: 101
  Total rules: ~2000
  Validated rules: ~1800
  Validation rate: ~90%
```

## Final Results

After completion:

```bash
# View summary
cat sequential_run.log | tail -50

# Check all files created
ls -lh output/

# Count YAMLs
ls output/*.yaml | wc -l

# View final stats
python3 << 'EOF'
import json
with open('output/requirements_validated.json') as f:
    data = json.load(f)
    
print(f"Services: {len(data)}")
print(f"Total rules: {sum(len(r) for r in data.values())}")
print(f"Validated: {sum(1 for s in data.values() for r in s if r.get('all_fields_valid'))}")
EOF
```

## System Sleep Prevention

The script uses `caffeinate` which:
- ✅ Prevents display sleep
- ✅ Prevents disk sleep  
- ✅ Prevents system sleep
- ✅ Prevents idle sleep

Your Mac will stay awake until the process completes!

## Quick Status Check Script

Save this for easy monitoring:

```bash
#!/bin/bash
echo "=== Sequential Run Status ==="
echo ""
echo "Process running:"
ps aux | grep run_sequential_all | grep -v grep || echo "  Not running"
echo ""
echo "Log tail:"
tail -10 /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/Agent-rulesid-rule-yaml/sequential_run.log
echo ""
echo "Output files:"
ls -lh /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/Agent-rulesid-rule-yaml/output/ 2>/dev/null | tail -5
```

Good luck! 🚀

