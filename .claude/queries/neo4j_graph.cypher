// Graph overview — node counts by label
MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC;

// Relationship type counts
MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC;

// Resources with threats for tenant
MATCH (r:Resource)-[:HAS_THREAT]->(t)
WHERE r.tenant_id = $tenant_id
RETURN r.resource_uid, r.resource_type, r.service, count(t) AS threats
ORDER BY threats DESC LIMIT 20;

// Internet-exposed resources
MATCH (i:Internet)-[:EXPOSES]->(r)
RETURN r.resource_uid, r.resource_type, r.service LIMIT 20;

// Attack paths: Internet to storage
MATCH path = (i:Internet)-[*1..4]->(target:Resource)
WHERE target.resource_type IN ['s3.bucket', 'rds.instance', 'dynamodb.table']
RETURN path LIMIT 10;

// Blast radius from resource
MATCH (r:Resource {resource_uid: $uid})-[rel*1..3]-(connected:Resource)
RETURN DISTINCT connected.resource_uid, connected.resource_type,
       [r IN rel | type(r)] AS path_types LIMIT 50;

// Subgraph: resources with relationships
MATCH (a:Resource)-[r]-(b:Resource)
WHERE a.tenant_id = $tenant_id
RETURN a.resource_uid, type(r) AS rel, b.resource_uid LIMIT 100;
