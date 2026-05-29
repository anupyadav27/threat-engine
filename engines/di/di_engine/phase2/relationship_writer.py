"""
REMOVED — DI relationship writer deleted.

Relationship edges are now written by the owning security engines directly
to asset_relationships in the DI DB via engine_common.relationship_writer:

  Network engine  → topology edges (GOVERNED_BY, ROUTES_VIA, PEERED_WITH,
                     CONNECTED_VIA, HAS_ENDPOINT, PROTECTED_BY, INTERNET_ACCESSIBLE)
  IAM engine      → identity edges (ASSUMES, HAS_POLICY, MEMBER_OF)
  Encryption      → data-plane edges (ENCRYPTED_BY, GRANTS_DECRYPT_TO)

Attack-path engine reads asset_relationships after all engines complete.
"""

# Kept as an empty module so any stale import does not crash the process.
