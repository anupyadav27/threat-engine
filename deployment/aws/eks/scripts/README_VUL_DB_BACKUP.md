# Vul DB backup to S3 (Mumbai)

## What we have

- **RDS (ap-south-1):** one instance  
  - **Identifier:** `postgres-vulnerability-db`  
  - **Endpoint:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com`  
  - **Engine:** PostgreSQL **15.12**
- **Database:** `vulnerability_db` (vul-related DB on that instance)
- **S3:** bucket `cspm-lgtech`, region `ap-south-1`. Backup path: **`vul-db-backup/`**

## Backup and push to S3

Run from a host that can reach the RDS (same VPC, VPN, or RDS is publicly accessible).

1. Set the DB password (from your secrets; not committed in this script):
   ```bash
   export VUL_DB_PASSWORD='<postgres-password>'
   ```
2. Use Postgres 15 for `pg_dump` (RDS is 15.12). Either:
   - Install PostgreSQL 15 client and run the script, or
   - Use Docker:
   ```bash
   cd deployment/aws/eks/scripts
   chmod +x backup-vul-db-to-s3.sh
   USE_DOCKER=1 VUL_DB_PASSWORD='<password>' ./backup-vul-db-to-s3.sh
   ```
3. Backup file will be created and uploaded to:
   `s3://cspm-lgtech/vul-db-backup/vulnerability_db_YYYYMMDD_HHMMSS.sql`

## Optional env vars

- `VUL_DB_HOST` – default: Mumbai RDS endpoint above  
- `VUL_DB_PORT` – default: 5432  
- `VUL_DB_USER` – default: postgres  
- `VUL_DB_NAME` – default: vulnerability_db  
- `S3_BUCKET` – default: cspm-lgtech  
- `AWS_REGION` – default: ap-south-1  
- `USE_DOCKER=1` – run `pg_dump` via `postgres:15-alpine` (use if local pg_dump is not 15.x)

## Restore (recover database from backup)

Yes — the `.sql` file in S3 is a full logical backup and can be used to recover the database.

1. Download the backup from S3:
   ```bash
   aws s3 cp s3://cspm-lgtech/vul-db-backup/vulnerability_db_YYYYMMDD_HHMMSS.sql . --region ap-south-1
   ```
2. Restore into an empty database (same name or new):
   ```bash
   # Create empty DB if needed: psql -h HOST -U postgres -d postgres -c "CREATE DATABASE vulnerability_db;"
   psql -h <rds-endpoint> -p 5432 -U postgres -d vulnerability_db -f vulnerability_db_YYYYMMDD_HHMMSS.sql
   ```
   Or with Docker (Postgres 15): `docker run --rm -i -e PGPASSWORD -e PGHOST -e PGUSER postgres:15-alpine psql -h $PGHOST -U postgres -d vulnerability_db < vulnerability_db_YYYYMMDD_HHMMSS.sql`

The backup is plain SQL (`-F p`), so `psql -f` is the correct way to restore.

## If backup times out

- Run the script with no timeout (e.g. in your terminal): `USE_DOCKER=1 VUL_DB_PASSWORD='...' ./backup-vul-db-to-s3.sh`
- Ensure the host can reach the RDS (security groups, VPC, VPN).
- Run from a pod inside the EKS cluster or a bastion in the same VPC if your laptop cannot reach RDS.
