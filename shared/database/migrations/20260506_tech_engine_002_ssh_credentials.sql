-- TE6-09: Add SSH credential columns to tech_credentials
-- sudo_required: whether to prepend sudo to all commands
-- ssh_private_key: reserved column — actual key content MUST live in AWS Secrets Manager,
--   referenced by credential_ref. This column is intentionally left NULL for ssh_key type.
--   Only the ARN is stored in credential_ref.

BEGIN;

ALTER TABLE tech_credentials
    ADD COLUMN IF NOT EXISTS sudo_required   BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS ssh_private_key TEXT    DEFAULT NULL;

COMMENT ON COLUMN tech_credentials.sudo_required   IS 'Prepend sudo to all SSH commands';
COMMENT ON COLUMN tech_credentials.ssh_private_key IS 'RESERVED — never store key content here. Key lives in AWS Secrets Manager; ARN stored in credential_ref.';

COMMIT;
