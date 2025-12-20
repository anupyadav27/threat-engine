# GCP Discovery API Approach - Full Coverage

## Current Status

- **GCP Database**: 35 services (Discovery API-based) ✅
- **AWS Database**: 411 services  
- **Azure Database**: 160 services

**GCP has 8.5% of AWS coverage** - we need to expand to get full coverage.

## Strategy: Use Discovery API Only

To maintain consistency and avoid conflicts, we should:
1. ✅ Use **Discovery API** as the single source (already in place)
2. ✅ Expand service discovery to find ALL available GCP services
3. ❌ Remove Python SDK discovery (causes conflicts)

## Discovery API Benefits

- ✅ Consistent structure with existing 35 services
- ✅ Complete API documentation (methods, parameters, schemas)
- ✅ Official Google source
- ✅ No package installation conflicts
- ✅ Easy to regenerate

## Next Steps

1. **Install Discovery API client**:
   ```bash
   pip install google-api-python-client
   ```

2. **Run full discovery**:
   ```bash
   python3 generate_all_gcp_services_from_discovery_api.py
   ```

3. **Expand service list** - The script will:
   - Query Discovery API for ALL available services
   - Filter for GCP services
   - Generate enriched catalogs
   - Match existing structure

## Expected Outcome

- Discover 100+ GCP services (all available)
- Generate enriched database matching AWS/Azure structure
- Full coverage for compliance scanning

