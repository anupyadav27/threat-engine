# Why 27 Regions?

**Question**: How is it possible to scan 27 regions?

**Answer**: AWS has 27+ standard regions globally, and the scan script is configured to scan **ALL** of them.

---

## 🌍 AWS Global Regions

AWS operates data centers in **27 standard regions** worldwide (as of 2024-2025):

### Breakdown by Geography

#### United States (4 regions)
1. `us-east-1` - N. Virginia
2. `us-east-2` - Ohio
3. `us-west-1` - N. California
4. `us-west-2` - Oregon

#### Asia Pacific (10 regions)
5. `ap-south-1` - Mumbai
6. `ap-south-2` - Hyderabad
7. `ap-southeast-1` - Singapore
8. `ap-southeast-2` - Sydney
9. `ap-southeast-3` - Jakarta
10. `ap-southeast-4` - Melbourne
11. `ap-northeast-1` - Tokyo
12. `ap-northeast-2` - Seoul
13. `ap-northeast-3` - Osaka
14. `ap-east-1` - Hong Kong

#### Europe (7 regions)
15. `eu-central-1` - Frankfurt
16. `eu-central-2` - Zurich
17. `eu-west-1` - Ireland
18. `eu-west-2` - London
19. `eu-west-3` - Paris
20. `eu-north-1` - Stockholm
21. `eu-south-1` - Milan

#### Middle East (2 regions)
22. `me-south-1` - Bahrain
23. `me-central-1` - UAE

#### Others (4 regions)
24. `ca-central-1` - Canada
25. `sa-east-1` - São Paulo (South America)
26. `af-south-1` - Cape Town (Africa)
27. `il-central-1` - Israel

**Total: 27 regions**

---

## 🔍 Why Scan All Regions?

### Current Configuration
The scan script (`run_full_discovery_all_services.py`) is configured to scan **ALL** 27 regions by default.

**Reason**: 
- Comprehensive coverage
- Discover resources in any region
- Complete inventory

### Alternative: Scan Only Enabled Regions

If you want to scan only regions that are **enabled for your account**, you can modify the script to use:

```python
# Instead of hardcoded list, use:
import boto3
ec2 = boto3.client('ec2')
enabled_regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
```

This would typically return **fewer regions** (only those enabled/opted-in for your account).

---

## 📊 Current Scan Results

From the scan logs, we can see EC2 was scanned in all 27 regions:
- `us-east-1`, `us-east-2`, `us-west-1`, `us-west-2`
- `ap-south-1`, `ap-south-2`, `ap-southeast-1`, `ap-southeast-2`, `ap-southeast-3`, `ap-southeast-4`
- `ap-northeast-1`, `ap-northeast-2`, `ap-northeast-3`, `ap-east-1`
- `eu-central-1`, `eu-central-2`, `eu-west-1`, `eu-west-2`, `eu-west-3`, `eu-north-1`, `eu-south-1`
- `me-south-1`, `me-central-1`
- `ca-central-1`, `sa-east-1`, `af-south-1`, `il-central-1`

**Total: 27 regions** ✅

---

## 💡 Notes

1. **Not all regions may have resources**: Some regions might return 0 items (expected)
2. **Some operations may fail**: Some AWS services/operations aren't available in all regions
3. **Global services**: Services like IAM, Route53 are scanned once (not per region)
4. **Regional services**: Services like EC2, S3 are scanned in each region

---

## 🎯 Summary

**27 regions is correct** - AWS has 27 standard regions globally, and the scan script is configured to scan all of them for comprehensive coverage.

If you want to limit to only enabled regions for your account, we can modify the script to use `describe_regions()` instead of the hardcoded list.

---

**Last Updated**: 2026-01-22T07:20:00

