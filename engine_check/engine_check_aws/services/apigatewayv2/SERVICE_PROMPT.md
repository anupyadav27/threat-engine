# APIGATEWAYV2 Service Processing Prompt

## Task
Process APIGATEWAYV2 service metadata mapping and YAML generation following this sequence:

1. **Review all metadata from APIGATEWAYV2**
   - Review all metadata files in `/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/apigatewayv2/metadata/`
   - Understand security requirements and intent

2. **Create metadata_mapping.json**
   - Use boto3 database files from `/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/apigatewayv2/`
   - Reference:
     - `direct_vars.json` (for available fields and operators)
     - `dependency_index.json` (for operation relationships)
     - `boto3_dependencies_with_python_names_fully_enriched.json` (for method details)
   - Generate mappings with correct:
     - `python_method` (exact boto3 method name)
     - `response_path` (actual API response structure)
     - `logical_operator` (null, "all", or "any")
     - `nested_field` (fields with paths, expected values, operators)

3. **Review as AWS Python developer and security expert**
   - Verify methods exist in boto3 APIGATEWAYV2 client
   - Verify field paths match actual API responses
   - Verify operators are appropriate for field types
   - Verify security intent is correctly mapped

4. **Generate YAML from metadata_mapping.json**
   - Run: `cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine && python3 generate_yaml_from_metadata_mapping.py apigatewayv2`
   - Verify YAML file is created in `services/apigatewayv2/rules/apigatewayv2.yaml`

5. **MANDATORY: Test with actual AWS resources**
   > **CRITICAL**: This step is MANDATORY and cannot be skipped. Testing with actual resources is the only way to verify:
   > - The YAML executes without errors
   > - Field paths are correct
   > - All checks actually run (not just 0 checks because no resources exist)
   > - The compliance engine can discover and evaluate resources correctly
   > - Check conditions evaluate correctly (not all passing/failing incorrectly)
   
   **Step 5a: Check for existing resources**
   ```bash
   # Check if resources exist in your AWS account
   cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
   python3 -c "
   import boto3
   from auth.aws_auth import get_boto3_session
   session = get_boto3_session()
   client = session.client('apigatewayv2', region_name='us-east-1')
   # List resources (adjust method name as needed)
   try:
       resources = client.list_*()  # Replace with appropriate list method
       print(f'Found {{len(resources)}} existing resources')
   except Exception as e:
       print(f'No resources found or error: {{e}}')
   "
   ```
   
   **Step 5b: Use existing resources OR create test resources**
   
   **Option A: Use existing resources (if available)**
   - If resources exist, document which ones you're using
   - Proceed directly to Step 5c (Run compliance scan)
   - **Note**: Using existing resources is acceptable, but ensure they cover the compliance scenarios you're testing
   
   **Option B: Create test resources (if none exist)**
   - **REQUIRED**: Create a test script: `test_apigatewayv2_resources.py`
   - Use existing test scripts as templates:
     - `test_efs_resources.py` (for file system services)
     - `test_elasticache_resources.py` (for database/cache services)
     - `test_eip_resources.py` (for network services)
   - The test script MUST:
     1. **Create resources** with configurations that test compliance rules:
        - Some resources configured COMPLIANT (should PASS checks)
        - Some resources configured NON-COMPLIANT (should FAIL checks)
        - Wait for resources to be fully available (use AWS waiters)
     2. **Run compliance scan** automatically:
        ```python
        subprocess.run([
            sys.executable, '-m', 'aws_compliance_python_engine.engine.main_scanner',
            '--service', 'apigatewayv2', '--region', 'us-east-1'
        ])
        ```
     3. **Destroy all test resources** (even on failure - use try/finally)
     4. **Handle errors gracefully** and ensure cleanup
   - Run the test script:
     ```bash
     cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
     python3 test_apigatewayv2_resources.py
     ```
   - **DO NOT SKIP** resource creation - this is the only way to verify the YAML works correctly
   - **Expected time**: Resource creation can take 5-15 minutes depending on service
   
   **Step 5c: Run compliance scan**
   ```bash
   cd /Users/apple/Desktop/threat-engine
   python3 -m aws_compliance_python_engine.engine.main_scanner --service apigatewayv2 --region us-east-1
   ```
   
   **Step 5d: Verify scan execution (MANDATORY CHECKS)**
   - ✅ **Scan completes** without crashing or hanging
   - ✅ **Check count**: If resources exist, `total_checks > 0` (verify in `output/scan_*/index.json`)
   - ✅ **No execution errors**: `output/scan_*/logs/errors.log` is empty or only contains expected warnings
   - ✅ **No critical errors**: Review `output/scan_*/logs/scan.log` - no ERROR or CRITICAL messages
   - ✅ **Field paths correct**: Check evidence JSON files show correct field values (not null/undefined)
   - ✅ **Check evaluation**: Some checks PASS and some FAIL (not all passing/failing incorrectly)
   
   **Step 5e: Analyze scan results**
   ```bash
   # Find the latest scan folder
   LATEST_SCAN=$(ls -td output/scan_* | head -1)
   
   # Check for errors
   cat $LATEST_SCAN/logs/errors.log
   
   # Check scan summary
   cat $LATEST_SCAN/index.json | jq '.summary'
   
   # Check individual check results
   find $LATEST_SCAN -name "*.json" -path "*/apigatewayv2/*" | head -5 | xargs cat
   ```
   
   **What to verify in check results:**
   - Field paths in evidence match the YAML `var` paths
   - Field values are not null/undefined (indicates incorrect path)
   - Operators are appropriate for field types
   - Check conditions evaluate correctly (PASS/FAIL makes sense)
   - All expected checks executed (count matches number of rules in metadata)

6. **Detailed output analysis (MANDATORY)**
   
   **6a: Check for execution errors**
   ```bash
   LATEST_SCAN=$(ls -td output/scan_* | head -1)
   
   # Check errors log
   if [ -s "$LATEST_SCAN/logs/errors.log" ]; then
       echo "❌ ERRORS FOUND:"
       cat "$LATEST_SCAN/logs/errors.log"
   else
       echo "✅ No errors in errors.log"
   fi
   
   # Check scan log for ERROR/CRITICAL
   if grep -i "ERROR\|CRITICAL" "$LATEST_SCAN/logs/scan.log"; then
       echo "❌ ERRORS FOUND in scan.log"
   else
       echo "✅ No ERROR/CRITICAL messages in scan.log"
   fi
   ```
   
   **6b: Verify check execution**
   ```bash
   # Check total checks executed
   TOTAL_CHECKS=$(cat $LATEST_SCAN/index.json | jq '.summary.total_checks')
   echo "Total checks executed: $TOTAL_CHECKS"
   
   # If resources exist but checks = 0, this indicates a YAML problem
   if [ "$TOTAL_CHECKS" -eq 0 ]; then
       echo "⚠️  WARNING: 0 checks executed"
       echo "   - If resources exist, this indicates YAML discovery/check issues"
       echo "   - Check discovery methods are correct"
       echo "   - Check for_each dependencies are correct"
   fi
   ```
   
   **6c: Verify field paths in check evidence**
   ```bash
   # Sample a few check result files
   find $LATEST_SCAN -name "*.json" -path "*/apigatewayv2/*" | head -3 | while read file; do
       echo "Checking: $file"
       cat "$file" | jq '.evidence'  # Review field paths and values
   done
   ```
   
   **Common issues to check:**
   - ❌ **Field path errors**: Evidence shows `null` or `undefined` → field path is wrong
     - Example: `item.CacheClusters.Field` should be `item.Field` (if items_for iterates over CacheClusters)
   - ❌ **Missing for_each dependencies**: Discovery fails with "missing parameter" → add for_each dependency
   - ❌ **Incorrect operator types**: Check always passes/fails → wrong operator for field type
     - Example: Using `equals` for boolean when should use `exists`
   - ❌ **Missing required parameters**: Discovery call fails → check operation_registry.json for required params
   - ❌ **Incorrect response paths**: Discovery returns empty → wrong response_path in metadata_mapping.json
   - ❌ **All checks pass/fail**: Indicates check condition logic is wrong

7. **Fix issues and retest (iterative process)**
   
   **7a: Fix identified issues**
   - If field path errors: Fix `metadata_mapping.json` → regenerate YAML
   - If discovery errors: Fix `rules/apigatewayv2.yaml` directly or fix `metadata_mapping.json`
   - If check condition errors: Fix `metadata_mapping.json` (operator, expected_value)
   
   **7b: Regenerate YAML (if metadata_mapping.json changed)**
   ```bash
   cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine
   python3 generate_yaml_from_metadata_mapping.py apigatewayv2
   ```
   
   **7c: RETEST with actual resources (MANDATORY)**
   - Repeat Step 5 (create resources OR use existing, run scan, verify results)
   - **DO NOT** skip retesting - fixes must be validated
   
   **7d: Continue until all criteria met**
   - ✅ No execution errors (errors.log empty, no ERROR/CRITICAL in scan.log)
   - ✅ All checks execute (total_checks > 0 if resources exist)
   - ✅ Field paths correct (evidence shows actual values, not null)
   - ✅ Check conditions evaluate correctly (some PASS, some FAIL as expected)
   - ✅ All expected checks ran (count matches number of rules in metadata)
   
   **7e: Add completion comment to YAML**
   ```yaml
   # STATUS: ✅ COMPLETE AND TESTED
   # - metadata_mapping.json created and reviewed
   # - YAML generated and tested against AWS
   # - All {N} checks executed successfully ({X} accounts, {Y} total checks)
   # - 0 execution errors
   # - Field paths verified correct in check evidence
   # - Test resources: {created/destroyed OR used existing: <resource-ids>}
   # - Tested: {DATE}
   ```

## Success Criteria
- ✅ All metadata files reviewed
- ✅ metadata_mapping.json created with correct boto3 methods and fields
- ✅ YAML generated successfully
- ✅ **Test resources created OR existing resources used for testing**
- ✅ **Compliance scan executed with actual resources**
- ✅ **Output logs reviewed - no execution errors**
- ✅ **All checks executed (total_checks > 0 if resources exist)**
- ✅ **Field paths verified correct in check evidence**
- ✅ **Test resources destroyed (if created)**
- ✅ Completion comment added to YAML

## Important Notes
- **DO NOT** mark a service as complete without testing with actual resources
- **DO NOT** skip testing because "YAML structure looks correct" - actual execution is required
- **DO NOT** proceed to next service if current service has execution errors
- If resources cannot be created (cost/access issues), document this and use existing resources if available
- Always check the output folder logs - they provide the best feedback on YAML correctness

