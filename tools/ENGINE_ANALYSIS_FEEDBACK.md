# Engine Analysis & Agentic AI Feedback Guide

## Why Engine Scan Results Weren't Visible

### Issue Identified
The analysis script reported "No results found for acm" because:
1. **Last scan was for `accessanalyzer`, not `acm`**
   - The scan log shows: `Services: 1 - ['accessanalyzer']`
   - Results are saved per-service in format: `{account_id}_{region}_{service}_checks.json`

2. **Inventory/Discovery Results Not Saved to Files**
   - The engine saves discovery results in memory but only writes check results to files
   - `save_reporting_bundle()` in `reporting_manager.py` only saves checks, not inventory
   - This limits analysis capabilities

### Solution Implemented
✅ Updated `analyze_engine_output.py` to:
- Better file pattern matching (handles both regional and global services)
- Extract inventory from check evidence fields (limited but better than nothing)
- Provide helpful error messages showing available services
- Show clear instructions on how to run a scan for the requested service

## How Analysis Provides Feedback for Agentic AI

### 1. Discovery Execution Issues

The analysis identifies:
- **Empty Discoveries**: Discoveries that returned no data
- **Dependency Issues**: Discoveries that failed because their dependencies are empty
- **Not Executed**: Discoveries that were never called (syntax errors, missing fields)

**Feedback for Agentic AI:**
```
❌ Discovery aws.accessanalyzer.list_analyzers was not executed
   Suggestion: Check discovery structure - may have syntax errors or missing required fields
```

**Improvements:**
- Validate discovery YAML structure before generation
- Ensure all required fields (`discovery_id`, `calls`, `emit`) are present
- Check that `action` names match actual boto3 method names

### 2. Check Field Mapping Issues

The analysis identifies:
- **Missing Fields**: Checks reference fields that don't exist in discovery emit
- **Field Name Mismatches**: Case sensitivity, snake_case vs camelCase issues

**Feedback for Agentic AI:**
```
❌ Check aws.acm.certificate.key_length_minimum references field "KeyAlgorithm" 
   not found in discovery aws.acm.list_certificates
   Available fields: certificate_arn, domain_name, status, key_algorithm
   Suggestion: Use exact field names from emit.item in discovery
```

**Improvements:**
- Match field names exactly from `emit.item` in discovery
- Use field name normalization (snake_case) consistently
- Verify field paths in emit templates match API response structure

### 3. Dependency Chain Issues

The analysis identifies:
- **Circular Dependencies**: Discoveries that depend on each other
- **Dependency Order**: Dependencies defined after dependent discoveries
- **Broken Dependencies**: Parameter mapping failures

**Feedback for Agentic AI:**
```
❌ Discovery aws.acm.describe_certificate returned empty despite 
   dependency aws.acm.list_certificates having 5 items
   Suggestion: Check parameter mapping in params - field names may be incorrect
```

**Improvements:**
- Verify parameter mapping from dependency to dependent discovery
- Check if field names in `params` match emit field names
- Ensure dependency discovery executes successfully before dependent

### 4. Emit Template Issues

The analysis identifies:
- **Empty Fields**: Emit templates not extracting data correctly
- **Wrong Paths**: Template paths don't match API response structure

**Feedback for Agentic AI:**
```
❌ Discovery aws.acm.list_certificates returned items but 8/15 fields are empty
   Suggestion: Check emit template - field paths may be incorrect or API response structure differs
```

**Improvements:**
- Verify template paths match actual API response structure
- Test templates with real API responses
- Use source spec field metadata for accurate paths

## Running Analysis for Feedback

### Step 1: Run Engine Scan
```bash
cd aws_compliance_python_engine
source venv/bin/activate
export PYTHONPATH=$(pwd):$PYTHONPATH
python engine/main_scanner.py --service acm --region us-east-1
```

### Step 2: Analyze Results
```bash
cd /Users/apple/Desktop/threat-engine
python3 tools/analyze_engine_output.py acm
```

### Step 3: Review Feedback
The analysis generates:
- **Console Output**: Summary of issues and suggestions
- **JSON Report**: `tools/engine_analysis_{service}_{timestamp}.json` with detailed findings

### Step 4: Improve Agentic AI
Use the feedback to:
1. **Fix Field Mappings**: Update `generate_rules.py` to use correct field names
2. **Improve Dependency Detection**: Enhance dependency chain logic
3. **Validate Templates**: Add validation for emit template paths
4. **Handle Edge Cases**: Add error handling for empty discoveries

## Example Feedback Loop

1. **Generate Rules**: `python tools/generate_rules.py --service acm`
2. **Run Engine**: `python engine/main_scanner.py --service acm --region us-east-1`
3. **Analyze**: `python tools/analyze_engine_output.py acm`
4. **Review Issues**: Check `engine_analysis_acm_*.json` for specific problems
5. **Fix Generator**: Update `generate_rules.py` based on feedback
6. **Repeat**: Iterate until all issues resolved

## Current Limitations

1. **Inventory Not Saved**: Discovery results are only in memory, limiting analysis
   - **Workaround**: Extract from check evidence (limited)
   - **Future**: Modify engine to save inventory separately

2. **Field Extraction**: Can't fully reconstruct discovery items from checks
   - **Workaround**: Use evidence fields as proxy
   - **Future**: Save full discovery results to files

3. **Real-time Feedback**: Analysis happens after scan completes
   - **Future**: Add real-time validation during rule generation

## Next Steps

1. ✅ **Done**: Improved analysis script with better error messages
2. 🔄 **In Progress**: Extract inventory from check evidence
3. 📋 **Todo**: Modify engine to save discovery results to files
4. 📋 **Todo**: Add validation during rule generation (pre-scan)
5. 📋 **Todo**: Create automated feedback loop for continuous improvement

