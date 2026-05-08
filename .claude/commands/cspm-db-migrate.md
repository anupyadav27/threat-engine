# /cspm-db-migrate

Apply a database migration to a CSPM engine database.

## Usage
```
/cspm-db-migrate <migration-file> <db-name>
```

Example:
```
/cspm-db-migrate 0013_new_engine_schema.sql threat_engine_new
```

## Migration file location
All migrations: `shared/database/migrations/`
Naming convention: `<NNNN>_<description>.sql`

## Steps

1. **Verify migration** — Read the SQL, check for data loss risks
2. **Copy to pod** — `kubectl cp shared/database/migrations/<file>.sql threat-engine-engines/<pod>:/tmp/<file>.sql`
3. **Apply migration** — `kubectl exec -n threat-engine-engines <pod> -- psql -h $DB_HOST -U $DB_USER -d <db-name> -f /tmp/<file>.sql`
4. **Verify applied** — Run `SELECT COUNT(*) FROM <new_table>` or `\d <new_table>`
5. **Update schema** — Update `shared/database/schemas/<engine>_schema.sql` to reflect current state

## Safety checklist before applying
- [ ] Migration is additive (no DROP TABLE, no DROP COLUMN without backup)
- [ ] Migration includes `IF NOT EXISTS` where appropriate
- [ ] Migration is idempotent (safe to re-run)
- [ ] Schema file updated to match

## Pod selection
Use a pod from the target engine (it has the right DB credentials):
```bash
kubectl get pods -n threat-engine-engines -l app=engine-<engine> -o jsonpath='{.items[0].metadata.name}'
```
