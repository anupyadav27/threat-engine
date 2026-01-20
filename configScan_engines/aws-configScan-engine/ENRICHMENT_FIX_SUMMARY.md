# Inventory Enrichment - Root Cause & Fix

## 🎯 ROOT CAUSE FOUND!

**Issue:** Dependent discovery emit templates use `{{ item.Name }}` but the `item` object doesn't contain the bucket name when the emit phase runs.

### Evidence:
```
Sample independent item: Name=aiwebsite01, name=None, resource_name=aiwebsite01
Sample dependent item: Name=, name=None  ← EMPTY!
```

### Why This Happens:
1. `for_each` discoveries execute 21 API calls (one per bucket)
2. Each call stores: `{'response': boto3_response, 'item': bucket_from_list_buckets, 'context': ...}`
3. During emit, it uses `item` from `acc_data['item']`
4. BUT the `item` object structure depends on what `list_buckets` emitted
5. `list_buckets` emits items with `resource_arn`, `resource_name`, `Name`, etc.
6. However, when resolving `'{{ item.Name }}'` in the emit context, something is wrong

### The Real Problem:
Looking at line 2759 in service_scanner.py:
```python
emit_context = {'response': response, 'item': item}
```

The `item` should be the bucket object from `list_buckets`, but when the template `'{{ item.Name }}'` is resolved, it's coming back empty.

## ✅ THE FIX

The issue is that `item` in `acc_data` is the ORIGINAL bucket from `list_buckets` emit, which has the structure from lines 20-25 of s3.yaml:
- `resource_arn`
- `resource_id` 
- `Name`
- etc.

So `item.Name` SHOULD work. Let me check if the template resolution is the issue...

Actually, looking more carefully at the logs:
```
Found 1 items in aws.s3.get_bucket_versioning, 21 items in aws.s3.list_buckets
```

Wait - **only 1 item in get_bucket_versioning!** That's the issue!

Even though 21 API calls succeed, only 1 emitted item is being created. This means the emit phase is only creating 1 item despite having 21 `accumulated_contexts`.

## 🔍 Next Investigation
Need to check why `discovery_results[discovery_id] = results` on line 2766 only has 1 item when `accumulated_contexts` has 21.

Most likely: The emit loop is being skipped or overwritten somewhere.

## 📝 Quick Test Needed
Add logging before line 2766 to confirm:
```python
logger.info(f"[EMIT] {discovery_id}: About to save {len(results)} results from {len(accumulated_contexts)} contexts")
```

If this shows 21 → 21, the problem is elsewhere.
If this shows 21 → 1, the emit loop has a bug.

