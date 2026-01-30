# Test file to trigger: Assigning high privileges Azure Active Directory built-in roles is security-sensitive

provider "azuread" {
  # Config details like client_id/secret/tenant_id would normally go here
}

# ❌ This resource assigns a forbidden high-privilege role
resource "azuread_user_assigned_role" "admin_role" {
  user_object_id        = "00000000-0000-0000-0000-000000000000"
  role_definition_name  = "Global Administrator"  # Should trigger the rule
}

# ❌ Another example: User Administrator role (also forbidden)
resource "azuread_user_assigned_role" "user_admin_role" {
  user_object_id        = "11111111-1111-1111-1111-111111111111"
  role_definition_name  = "User Administrator"  # Should also trigger the rule
}
