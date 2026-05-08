"""Blast radius computation via Neo4j graph traversal.

This is the ONLY subpackage in the entire platform that is allowed to set
blast_radius_score != 0. All other engines must hardcode blast_radius_score = 0.
"""
