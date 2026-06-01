-- di_020_iam_role_catalog.sql
-- Add iam_role and iam_user to di_resource_catalog with category='identity'
-- and subcategory='iam_role'/'iam_user' so crown_jewel_classifier routes them
-- through the is_admin_role / has_wildcard_policy conditional check.
--
-- Without this row the classifier's _load_from_di_catalog() never populates
-- _conditional_types for 'iam_role', so admin IAM roles are never classified as
-- crown jewels — PRIVILEGE_ESCALATION and ACCOUNT_TAKEOVER objectives get 0 paths.
--
-- The attack_objective_catalog already has:
--   iam_role → PRIVILEGE_ESCALATION (required_capability=can_assume)
-- so no change needed there.

DO $$
BEGIN
    -- iam_role: AWS IAM Role — admin roles become crown jewels (identity/iam_role)
    INSERT INTO di_resource_catalog (
        csp, service, resource_type, category, subcategory,
        classification, show_in_inventory, show_in_architecture,
        has_arn, canonical_type, loaded_at, updated_at
    ) VALUES (
        'aws', 'iam', 'iam_role', 'identity', 'iam_role',
        'identity_access', TRUE, FALSE,
        TRUE, 'iam_role', NOW(), NOW()
    )
    ON CONFLICT (csp, service, resource_type)
    DO UPDATE SET
        category    = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        updated_at  = NOW();

    -- iam_user: AWS IAM User — users with wildcard/admin policy become crown jewels
    INSERT INTO di_resource_catalog (
        csp, service, resource_type, category, subcategory,
        classification, show_in_inventory, show_in_architecture,
        has_arn, canonical_type, loaded_at, updated_at
    ) VALUES (
        'aws', 'iam', 'iam_user', 'identity', 'iam_user',
        'identity_access', TRUE, FALSE,
        TRUE, 'iam_user', NOW(), NOW()
    )
    ON CONFLICT (csp, service, resource_type)
    DO UPDATE SET
        category    = EXCLUDED.category,
        subcategory = EXCLUDED.subcategory,
        updated_at  = NOW();

    RAISE NOTICE 'di_020: iam_role + iam_user added to di_resource_catalog';
END $$;