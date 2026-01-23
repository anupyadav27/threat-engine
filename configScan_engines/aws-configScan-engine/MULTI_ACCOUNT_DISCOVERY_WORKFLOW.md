# Multi-Account Discovery Workflow

**Enhanced Engine Workflow**: Discover accounts → Discover enabled regions → Scan all combinations

---

## 🔄 Workflow Overview

### Current Workflow (Single Account)
1. ✅ Hardcoded account ID
2. ✅ Hardcoded 27 regions
3. ✅ Scan 1 account × 27 regions

### Enhanced Workflow (Multi-Account)
1. ✅ **Discover all accounts** (from AWS Organizations or current account)
2. ✅ **For each account, discover enabled regions** (using `describe_regions()`)
3. ✅ **Scan all (account, enabled_region) combinations**

---

## 📋 Step-by-Step Process

### Step 1: Discover Accounts

**Methods**:
1. **AWS Organizations** (if available):
   ```python
   org_client = session.client('organizations', region_name='us-east-1')
   accounts = org_client.list_accounts()
   ```
   - Returns all accounts in the organization
   - Includes account ID, name, email, status

2. **Fallback to Current Account**:
   ```python
   sts_client = session.client('sts')
   account_id = sts_client.get_caller_identity()['Account']
   ```
   - If Organizations not available or no access

3. **Specific Accounts** (manual list):
   - User provides list of account IDs

**Result**: List of accounts to scan

---

### Step 2: Discover Enabled Regions for Each Account

**Method**: Use `describe_regions()` for each account
```python
ec2_client = session.client('ec2', region_name='us-east-1')
response = ec2_client.describe_regions(AllRegions=True)

enabled_regions = [
    region['RegionName'] 
    for region in response.get('Regions', [])
    if region.get('OptInStatus') in (None, 'opt-in-not-required', 'opted-in')
]
```

**Result**: For each account, list of enabled regions

---

### Step 3: Generate Account-Region Combinations

**Example**:
- Account 1: `us-east-1`, `us-west-2`, `eu-west-1` (3 regions)
- Account 2: `us-east-1`, `ap-south-1` (2 regions)
- Account 3: `us-east-1` (1 region)

**Total Combinations**: 3 + 2 + 1 = 6 combinations

---

### Step 4: Scan All Combinations

For each (account, region) combination:
1. Register hierarchy in database
2. Run discovery scan for that account-region
3. Store results

---

## 🚀 Usage

### Basic Usage (Auto-Discover)
```bash
python3 run_multi_account_discovery.py --confirm
```

This will:
1. Discover all accounts from AWS Organizations
2. For each account, discover enabled regions
3. Scan all combinations

### Specific Accounts
```bash
python3 run_multi_account_discovery.py \
  --accounts 588989875114 123456789012 \
  --confirm
```

### Specific Regions (Override Enabled Regions)
```bash
python3 run_multi_account_discovery.py \
  --regions us-east-1 us-west-2 \
  --confirm
```

### Current Account Only (No Organizations)
```bash
python3 run_multi_account_discovery.py \
  --no-organizations \
  --confirm
```

---

## 📊 Example Output

```
================================================================================
STEP 1: DISCOVERING ACCOUNTS
================================================================================
  Found 3 accounts in organization

================================================================================
STEP 2: DISCOVERING ENABLED REGIONS FOR EACH ACCOUNT
================================================================================

  Processing account: Production (588989875114)
    Found 15 enabled regions

  Processing account: Development (123456789012)
    Found 8 enabled regions

  Processing account: Staging (987654321098)
    Found 12 enabled regions

================================================================================
STEP 3: SUMMARY
================================================================================
  Total Accounts: 3
  Total Account-Region Combinations: 35
    Production (588989875114): 15 regions
    Development (123456789012): 8 regions
    Staging (987654321098): 12 regions

================================================================================
STEP 4: SCANNING ALL ACCOUNT-REGION COMBINATIONS
================================================================================

  Scanning: Production (588989875114)
    Regions: 15 regions
    ✅ Completed: discovery_20260122_120000

  Scanning: Development (123456789012)
    Regions: 8 regions
    ✅ Completed: discovery_20260122_120500

  Scanning: Staging (987654321098)
    Regions: 12 regions
    ✅ Completed: discovery_20260122_121000
```

---

## 🔧 Implementation Details

### File: `run_multi_account_discovery.py`

**Key Functions**:
1. `discover_accounts_and_regions()`: Discovers accounts and enabled regions
2. `run_multi_account_discovery_scan()`: Orchestrates the full workflow

**Dependencies**:
- `utils/organizations_scanner.py`: Account and region discovery utilities
- `engine/scan_controller.py`: Scan execution
- `engine/database_manager.py`: Database operations

---

## 💡 Benefits

### Before (Hardcoded)
- ❌ Single account only
- ❌ All 27 regions (even if not enabled)
- ❌ Manual configuration

### After (Dynamic Discovery)
- ✅ Multiple accounts automatically
- ✅ Only enabled regions per account
- ✅ Automatic discovery
- ✅ Efficient scanning (no wasted API calls)

---

## 📝 Notes

1. **Cross-Account Access**: For multi-account scanning, you need:
   - AWS Organizations access (for account discovery)
   - Cross-account roles (for scanning other accounts)
   - Or use the same credentials for all accounts

2. **Region Discovery**: Uses `describe_regions()` which returns:
   - All available regions
   - Opt-in status for each region
   - Filters to only enabled/opted-in regions

3. **Parallel Processing**: Each account-region combination can be processed in parallel (configurable)

---

## 🎯 Summary

**Enhanced Workflow**:
1. ✅ Discover accounts (Organizations or current)
2. ✅ Discover enabled regions (per account)
3. ✅ Generate all (account, region) combinations
4. ✅ Scan all combinations

**Result**: Comprehensive multi-account, multi-region discovery scan

---

**Last Updated**: 2026-01-22T07:30:00

