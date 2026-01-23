# Additional Improvements Identified

**Date**: 2026-01-21  
**Scan Status**: 61/100 services (61%), 11,075 records, 0 errors

---

## 🔍 New Improvement Areas Identified

### 1. Database Write Bottleneck (CRITICAL) ⚠️

**Issue**: Database writes are happening one-by-one
- Each item calls `store_discovery()` individually
- Each item gets its own database connection
- Each item does a SELECT query to check previous version
- Each item does 2 INSERTs (discoveries + discovery_history)
- For 11,075 records = 11,075 SELECTs + 22,150 INSERTs

**Current Code**:
```python
for item in items_list:
    self.db.store_discovery(..., items=[item])  # One at a time!
```

**Impact**:
- **Major bottleneck** for high-volume services (EC2: 2,884 items)
- Each write = ~10-50ms = 2,884 items × 50ms = ~144 seconds just for DB writes
- Total DB overhead: ~11,075 records × 50ms = ~9 minutes of DB time

**Solution**: Batch inserts
- Collect all items for a discovery
- Single batch INSERT using `executemany()`
- Batch SELECT for previous versions
- **Expected Speedup**: 10-50x faster database writes

---

### 2. Redundant JSON Serialization ⚠️

**Issue**: JSON serialization happens multiple times
- Once in `store_discovery()` for `raw_response`
- Once in `store_discovery()` for `emitted_fields`
- Once in `append_service_output()` for NDJSON file
- Same data serialized 3 times

**Solution**: Serialize once, reuse
- Serialize JSON once per item
- Reuse serialized JSON for DB and file writes
- **Expected Speedup**: 2-3x faster for large items

---

### 3. Individual Database Connections ⚠️

**Issue**: Each `store_discovery()` call gets a new connection
- Connection pool overhead
- Connection acquisition/release per item
- For 11,075 records = 11,075 connection acquisitions

**Solution**: Reuse connection per batch
- Get connection once per discovery batch
- Process all items in batch
- Release connection after batch
- **Expected Speedup**: 5-10x faster connection handling

---

### 4. Redundant Previous Version Checks ⚠️

**Issue**: Each item does individual SELECT for previous version
- 11,075 individual SELECT queries
- Each query checks: discovery_id, resource_arn, customer_id, tenant_id, hierarchy_id
- Could be batched with single query

**Solution**: Batch SELECT for previous versions
- Single query: `SELECT ... WHERE discovery_id IN (...) AND resource_arn IN (...)`
- Build lookup map
- Use map for version checking
- **Expected Speedup**: 10-20x faster for version checks

---

## 📊 Performance Impact Analysis

### Current Performance
- **Scan Progress**: 61/100 services in ~52 minutes
- **Rate**: ~213 records/minute
- **DB Write Time**: Estimated ~9 minutes (17% of total time)

### With Batch Inserts
- **DB Write Time**: ~30-60 seconds (1% of total time)
- **Total Speedup**: 10-20% faster overall
- **For High-Volume Services**: 50-80% faster (EC2: 2,884 items)

---

## 🎯 Priority Implementation

### Priority 1: Batch Database Inserts (HIGHEST IMPACT)
- Implement `store_discoveries_batch()` method
- Use `executemany()` for bulk inserts
- Batch previous version checks
- **Expected Impact**: 10-50x faster DB writes

### Priority 2: Connection Reuse (MEDIUM IMPACT)
- Reuse connection per discovery batch
- Reduce connection pool overhead
- **Expected Impact**: 5-10x faster connection handling

### Priority 3: JSON Serialization Optimization (LOW-MEDIUM IMPACT)
- Serialize once, reuse multiple times
- **Expected Impact**: 2-3x faster for large items

---

## 📈 Expected Total Improvement

### Current
- 100 services: ~85 minutes (estimated)
- DB writes: ~15 minutes (17%)

### With All Optimizations
- 100 services: ~70-75 minutes
- DB writes: ~1-2 minutes (2%)
- **Total Speedup**: 10-15% faster overall
- **For High-Volume Services**: 50-80% faster

---

## ✅ Implementation Status

- [ ] Batch database inserts
- [ ] Connection reuse
- [ ] JSON serialization optimization
- [ ] Batch previous version checks

---

**Last Updated**: 2026-01-21T22:15:00

