#!/usr/bin/env node
/**
 * Threat Engine MCP Server
 *
 * Provides Claude with direct access to:
 * 1. PostgreSQL — all 9+ engine databases (read-only queries, schema introspection)
 * 2. Neo4j — Cypher queries against the security graph
 * 3. Engine APIs — OpenAPI spec fetching and health checks
 *
 * All queries are READ-ONLY. No mutations allowed.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import pg from "pg";
import neo4j from "neo4j-driver";
import { z } from "zod";
import http from "http";

// ─── Configuration ───────────────────────────────────────────────────────────

const PG_HOST = process.env.PG_HOST || "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com";
const PG_PORT = parseInt(process.env.PG_PORT || "5432");
const PG_USER = process.env.PG_USER || "postgres";
const PG_PASSWORD = process.env.PG_PASSWORD || "";

const NEO4J_URI = process.env.NEO4J_URI || "neo4j+s://17ec5cbb.databases.neo4j.io";
const NEO4J_USER = process.env.NEO4J_USER || "neo4j";
const NEO4J_PASSWORD = process.env.NEO4J_PASSWORD || "";

// All known databases
const DATABASES = [
  "threat_engine_discoveries",
  "threat_engine_check",
  "threat_engine_inventory",
  "threat_engine_threat",
  "threat_engine_compliance",
  "threat_engine_iam",
  "threat_engine_datasec",
  "threat_engine_onboarding",
  "threat_engine_risk",
  "threat_engine_secops",
];

// Engine API endpoints (when port-forwarded)
const ENGINE_PORTS = {
  inventory: 8022,
  check: 8002,
  threat: 8020,
  compliance: 8000,
  iam: 8003,
  datasec: 8004,
  discoveries: 8001,
  onboarding: 8010,
  risk: 8006,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Create a pg Pool for a specific database */
function getPool(database) {
  return new pg.Pool({
    host: PG_HOST,
    port: PG_PORT,
    user: PG_USER,
    password: PG_PASSWORD,
    database,
    max: 3,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    ssl: { rejectUnauthorized: false },
  });
}

// Pool cache
const pools = new Map();
function pool(database) {
  if (!pools.has(database)) {
    pools.set(database, getPool(database));
  }
  return pools.get(database);
}

/** Execute a read-only SQL query */
async function pgQuery(database, sql, params = []) {
  // Safety: block mutations
  const upper = sql.trim().toUpperCase();
  const forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "CREATE", "GRANT", "REVOKE"];
  for (const word of forbidden) {
    if (upper.startsWith(word)) {
      throw new Error(`Mutation blocked: ${word} statements are not allowed. This MCP is read-only.`);
    }
  }

  const client = await pool(database).connect();
  try {
    // Set statement timeout to 30s
    await client.query("SET statement_timeout = '30s'");
    const result = await client.query(sql, params);
    return {
      rows: result.rows,
      rowCount: result.rowCount,
      fields: result.fields?.map((f) => ({ name: f.name, dataTypeID: f.dataTypeID })),
    };
  } finally {
    client.release();
  }
}

/** Execute a read-only Cypher query */
async function neo4jQuery(cypher, params = {}) {
  // Safety: block mutations
  const upper = cypher.trim().toUpperCase();
  const forbidden = ["CREATE", "MERGE", "DELETE", "DETACH", "SET ", "REMOVE "];
  for (const word of forbidden) {
    if (upper.includes(word)) {
      throw new Error(`Mutation blocked: ${word} in Cypher is not allowed. This MCP is read-only.`);
    }
  }

  const driver = neo4j.driver(NEO4J_URI, neo4j.auth.basic(NEO4J_USER, NEO4J_PASSWORD));
  const session = driver.session({ defaultAccessMode: neo4j.session.READ });
  try {
    const result = await session.run(cypher, params);
    const records = result.records.map((r) => {
      const obj = {};
      r.keys.forEach((key) => {
        const val = r.get(key);
        obj[key] = neo4jToPlain(val);
      });
      return obj;
    });
    return {
      records,
      summary: {
        counters: result.summary.counters?.updates() || {},
        resultAvailableAfter: result.summary.resultAvailableAfter?.toNumber?.() || 0,
      },
    };
  } finally {
    await session.close();
    await driver.close();
  }
}

/** Convert Neo4j types to plain JS */
function neo4jToPlain(val) {
  if (val === null || val === undefined) return null;
  if (neo4j.isInt(val)) return val.toNumber();
  if (val instanceof neo4j.types.Node) {
    return { _type: "Node", labels: val.labels, properties: neo4jToPlain(val.properties), id: val.elementId };
  }
  if (val instanceof neo4j.types.Relationship) {
    return { _type: "Relationship", type: val.type, properties: neo4jToPlain(val.properties), start: val.startNodeElementId, end: val.endNodeElementId };
  }
  if (val instanceof neo4j.types.Path) {
    return { _type: "Path", segments: val.segments.map((s) => ({ start: neo4jToPlain(s.start), rel: neo4jToPlain(s.relationship), end: neo4jToPlain(s.end) })) };
  }
  if (Array.isArray(val)) return val.map(neo4jToPlain);
  if (typeof val === "object") {
    const out = {};
    for (const [k, v] of Object.entries(val)) out[k] = neo4jToPlain(v);
    return out;
  }
  return val;
}

/** HTTP GET helper */
function httpGet(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          resolve(data);
        }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
  });
}

// ─── MCP Server ──────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "threat-engine",
  version: "1.0.0",
  description: "Threat Engine CSPM — PostgreSQL, Neo4j, Engine APIs (read-only)",
});

// ─── Tool: pg_query ──────────────────────────────────────────────────────────

server.tool(
  "pg_query",
  `Execute a read-only SQL query against any Threat Engine database.
Databases: ${DATABASES.join(", ")}
Common scan ID columns: discovery_scan_id, check_scan_id, inventory_scan_id, threat_scan_id, compliance_scan_id, iam_scan_id, datasec_scan_id
All queries are READ-ONLY. Mutations (INSERT/UPDATE/DELETE) are blocked. 30s timeout.`,
  {
    database: z.enum(DATABASES).describe("Target database name"),
    sql: z.string().describe("SQL query (SELECT only)"),
    params: z.array(z.any()).optional().describe("Query parameters ($1, $2, ...)"),
  },
  async ({ database, sql, params }) => {
    try {
      const result = await pgQuery(database, sql, params || []);
      const text = JSON.stringify(result, null, 2);
      return { content: [{ type: "text", text: text.slice(0, 50000) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: pg_schema ─────────────────────────────────────────────────────────

server.tool(
  "pg_schema",
  "Get table schema (columns, types, constraints) for a specific table in any database.",
  {
    database: z.enum(DATABASES).describe("Target database name"),
    table: z.string().describe("Table name"),
  },
  async ({ database, table }) => {
    try {
      const cols = await pgQuery(database, `
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = $1 AND table_schema = 'public'
        ORDER BY ordinal_position
      `, [table]);

      const constraints = await pgQuery(database, `
        SELECT tc.constraint_name, tc.constraint_type, kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
        WHERE tc.table_name = $1 AND tc.table_schema = 'public'
        ORDER BY tc.constraint_type
      `, [table]);

      const indexes = await pgQuery(database, `
        SELECT indexname, indexdef FROM pg_indexes
        WHERE tablename = $1 AND schemaname = 'public'
      `, [table]);

      const count = await pgQuery(database, `SELECT COUNT(*) as count FROM ${table}`);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            table,
            database,
            row_count: count.rows[0]?.count,
            columns: cols.rows,
            constraints: constraints.rows,
            indexes: indexes.rows,
          }, null, 2),
        }],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: pg_tables ─────────────────────────────────────────────────────────

server.tool(
  "pg_tables",
  "List all tables in a database with row counts.",
  {
    database: z.enum(DATABASES).describe("Target database name"),
  },
  async ({ database }) => {
    try {
      const tables = await pgQuery(database, `
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name
      `);

      const results = [];
      for (const row of tables.rows) {
        try {
          const count = await pgQuery(database, `SELECT COUNT(*) as count FROM "${row.table_name}"`);
          results.push({ table: row.table_name, rows: count.rows[0]?.count });
        } catch {
          results.push({ table: row.table_name, rows: "error" });
        }
      }

      return { content: [{ type: "text", text: JSON.stringify(results, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: pg_databases ──────────────────────────────────────────────────────

server.tool(
  "pg_databases",
  "List all available Threat Engine databases.",
  {},
  async () => {
    return { content: [{ type: "text", text: JSON.stringify(DATABASES, null, 2) }] };
  }
);

// ─── Tool: neo4j_query ───────────────────────────────────────────────────────

server.tool(
  "neo4j_query",
  `Execute a read-only Cypher query against the Neo4j security graph.
The graph contains cloud resources as nodes with labels like :Resource, :Internet
and relationships like :HAS_THREAT, :EXPOSES, :CONNECTS_TO, :ASSUMES, :IN_VPC, :PROTECTED_BY, :LOGS_TO, :CONTAINS, :HOSTS
Mutations (CREATE/MERGE/DELETE/SET) are blocked. Use LIMIT to avoid large results.`,
  {
    cypher: z.string().describe("Cypher query (read-only)"),
    params: z.record(z.any()).optional().describe("Query parameters"),
  },
  async ({ cypher, params }) => {
    try {
      const result = await neo4jQuery(cypher, params || {});
      const text = JSON.stringify(result, null, 2);
      return { content: [{ type: "text", text: text.slice(0, 50000) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: neo4j_schema ──────────────────────────────────────────────────────

server.tool(
  "neo4j_schema",
  "Get Neo4j graph schema — node labels, relationship types, property keys, and counts.",
  {},
  async () => {
    try {
      const labels = await neo4jQuery("CALL db.labels() YIELD label RETURN label ORDER BY label");
      const relTypes = await neo4jQuery("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType ORDER BY relationshipType");
      const nodeCount = await neo4jQuery("MATCH (n) RETURN count(n) AS count");
      const relCount = await neo4jQuery("MATCH ()-[r]->() RETURN count(r) AS count");

      // Get sample properties per label
      const labelProps = [];
      for (const rec of labels.records.slice(0, 10)) {
        const lbl = rec.label;
        const props = await neo4jQuery(`MATCH (n:\`${lbl}\`) WITH n LIMIT 1 RETURN keys(n) AS props`);
        labelProps.push({ label: lbl, properties: props.records[0]?.props || [] });
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            node_labels: labels.records.map((r) => r.label),
            relationship_types: relTypes.records.map((r) => r.relationshipType),
            total_nodes: nodeCount.records[0]?.count,
            total_relationships: relCount.records[0]?.count,
            label_properties: labelProps,
          }, null, 2),
        }],
      };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: engine_api ────────────────────────────────────────────────────────

server.tool(
  "engine_api",
  `Call a Threat Engine API endpoint (via local port-forward). READ-ONLY GET requests only.
Available engines: ${Object.keys(ENGINE_PORTS).join(", ")}
Common endpoints: /health, /api/v1/health, /openapi.json
Requires active kubectl port-forward to the engine.`,
  {
    engine: z.enum(Object.keys(ENGINE_PORTS)).describe("Engine name"),
    path: z.string().describe("API path (e.g., /api/v1/health, /openapi.json)"),
  },
  async ({ engine, path }) => {
    try {
      const port = ENGINE_PORTS[engine];
      const url = `http://localhost:${port}${path}`;
      const result = await httpGet(url);
      const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
      return { content: [{ type: "text", text: text.slice(0, 50000) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}\nMake sure kubectl port-forward is active for ${engine} on port ${ENGINE_PORTS[engine]}` }], isError: true };
    }
  }
);

// ─── Tool: engine_openapi ────────────────────────────────────────────────────

server.tool(
  "engine_openapi",
  "Get the OpenAPI spec (endpoint list with methods and params) for an engine. Requires active port-forward.",
  {
    engine: z.enum(Object.keys(ENGINE_PORTS)).describe("Engine name"),
  },
  async ({ engine }) => {
    try {
      const port = ENGINE_PORTS[engine];
      const spec = await httpGet(`http://localhost:${port}/openapi.json`);

      // Extract just the endpoints summary (not the full spec)
      const paths = spec.paths || {};
      const summary = [];
      for (const [path, methods] of Object.entries(paths)) {
        for (const [method, details] of Object.entries(methods)) {
          const entry = {
            method: method.toUpperCase(),
            path,
            summary: details.summary || details.description || "",
          };
          // For POST, include request body schema ref
          if (method === "post" && details.requestBody?.content?.["application/json"]?.schema?.$ref) {
            const ref = details.requestBody.content["application/json"].schema.$ref;
            const schemaName = ref.split("/").pop();
            const resolved = spec.components?.schemas?.[schemaName];
            if (resolved) {
              entry.body_schema = {
                name: schemaName,
                required: resolved.required || [],
                properties: Object.fromEntries(
                  Object.entries(resolved.properties || {}).map(([k, v]) => [k, v.type || "any"])
                ),
              };
            }
          }
          summary.push(entry);
        }
      }

      return { content: [{ type: "text", text: JSON.stringify(summary, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: scan_status ───────────────────────────────────────────────────────

server.tool(
  "scan_status",
  `Check the status of recent scans across all CSPs. Shows scan_run_id, provider, overall_status,
engine_statuses (per-engine completion), and finding counts from all engine tables.
Use scan_run_id='latest' to get the most recent scan per provider.`,
  {
    scan_run_id: z.string().optional().describe("Specific scan_run_id, or omit for last 5 scans"),
    provider: z.string().optional().describe("Filter by provider: aws, azure, gcp, k8s, oci, ibm, alicloud"),
  },
  async ({ scan_run_id, provider }) => {
    try {
      let sql = `
        SELECT scan_run_id, provider, overall_status, started_at, completed_at,
               engines_requested, engines_completed, engine_statuses,
               EXTRACT(EPOCH FROM (COALESCE(completed_at, NOW()) - started_at))/60 AS duration_min
        FROM scan_runs
      `;
      const params = [];
      const where = [];
      if (scan_run_id) { where.push(`scan_run_id = $${params.length+1}`); params.push(scan_run_id); }
      if (provider)    { where.push(`provider = $${params.length+1}`); params.push(provider); }
      if (where.length) sql += ` WHERE ${where.join(" AND ")}`;
      sql += ` ORDER BY started_at DESC LIMIT 10`;

      const scans = await pgQuery("threat_engine_onboarding", sql, params);

      // For each scan, get finding counts across engines
      const results = [];
      for (const scan of scans.rows) {
        const sid = scan.scan_run_id;
        const counts = {};
        const engineQueries = [
          ["discoveries", "threat_engine_discoveries", "SELECT COUNT(*) as c FROM discovery_findings WHERE scan_run_id=$1"],
          ["check",       "threat_engine_check",       "SELECT COUNT(*) as c FROM check_findings WHERE scan_run_id=$1"],
          ["inventory",   "threat_engine_inventory",   "SELECT COUNT(*) as c FROM inventory_findings WHERE scan_run_id=$1"],
          ["threat",      "threat_engine_threat",       "SELECT COUNT(*) as c FROM threat_findings WHERE scan_run_id=$1"],
          ["iam",         "threat_engine_iam",          "SELECT COUNT(*) as c FROM iam_findings WHERE scan_run_id=$1"],
          ["datasec",     "threat_engine_datasec",      "SELECT COUNT(*) as c FROM datasec_findings WHERE scan_run_id=$1"],
          ["compliance",  "threat_engine_compliance",   "SELECT compliance_score FROM compliance_report WHERE scan_run_id=$1 LIMIT 1"],
        ];
        for (const [eng, db, q] of engineQueries) {
          try {
            const r = await pgQuery(db, q, [sid]);
            counts[eng] = r.rows[0]?.c ?? r.rows[0]?.compliance_score ?? 0;
          } catch { counts[eng] = "err"; }
        }
        results.push({ ...scan, finding_counts: counts });
      }

      return { content: [{ type: "text", text: JSON.stringify(results, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: rule_discoveries_status ───────────────────────────────────────────

server.tool(
  "rule_discoveries_status",
  `Check rule_discoveries table — how many service configs exist per CSP (provider), active vs disabled.
Use this to verify catalog sync is up-to-date and noise removal has been applied.`,
  {
    provider: z.string().optional().describe("Filter by provider: aws, azure, gcp, k8s, oci, ibm, alicloud"),
  },
  async ({ provider }) => {
    try {
      let sql = `
        SELECT provider, is_active, COUNT(*) as count,
               ARRAY_AGG(service ORDER BY service) FILTER (WHERE is_active = false) AS disabled_services
        FROM rule_discoveries
      `;
      const params = [];
      if (provider) { sql += ` WHERE provider = $1`; params.push(provider); }
      sql += ` GROUP BY provider, is_active ORDER BY provider, is_active`;

      const result = await pgQuery("threat_engine_check", sql, params);

      // Also get sample of active services per provider
      const providerSql = provider
        ? `SELECT service, boto3_client_name FROM rule_discoveries WHERE provider=$1 AND is_active=true ORDER BY service LIMIT 20`
        : `SELECT provider, COUNT(*) FILTER (WHERE is_active) as active, COUNT(*) FILTER (WHERE NOT is_active) as disabled FROM rule_discoveries GROUP BY provider ORDER BY provider`;

      const detail = await pgQuery("threat_engine_check", providerSql, provider ? [provider] : []);

      return { content: [{ type: "text", text: JSON.stringify({ summary: result.rows, detail: detail.rows }, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: cloud_accounts_status ─────────────────────────────────────────────

server.tool(
  "cloud_accounts_status",
  `List all onboarded cloud accounts with their credential status and last scan time.
Shows which CSPs are ready to scan and which need credentials/registration.`,
  {},
  async () => {
    try {
      const accounts = await pgQuery("threat_engine_onboarding", `
        SELECT account_id, provider, credential_type, credential_ref,
               account_status, account_onboarding_status,
               credential_validation_status, last_scan_at, created_at
        FROM cloud_accounts
        ORDER BY provider, created_at DESC
      `);

      const scans = await pgQuery("threat_engine_onboarding", `
        SELECT provider, MAX(started_at) as last_scan, COUNT(*) as total_scans,
               COUNT(*) FILTER (WHERE overall_status = 'completed') as completed_scans
        FROM scan_runs
        GROUP BY provider
      `);

      return { content: [{ type: "text", text: JSON.stringify({
        accounts: accounts.rows,
        scan_history: scans.rows
      }, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: finding_summary ────────────────────────────────────────────────────

server.tool(
  "finding_summary",
  `Get a cross-engine finding summary for a specific provider or scan.
Shows severity breakdown, top resource types, and compliance score.
Useful for validating a smoke test completed correctly.`,
  {
    scan_run_id: z.string().describe("scan_run_id to summarize"),
    provider: z.string().optional().describe("Provider filter (aws, azure, gcp, k8s)"),
  },
  async ({ scan_run_id, provider }) => {
    try {
      const results = {};

      // Discovery findings by resource type
      results.discoveries = await pgQuery("threat_engine_discoveries",
        `SELECT resource_type, COUNT(*) as count FROM discovery_findings
         WHERE scan_run_id=$1 ${provider ? "AND provider=$2" : ""}
         GROUP BY resource_type ORDER BY count DESC LIMIT 20`,
        provider ? [scan_run_id, provider] : [scan_run_id]
      );

      // Check findings by severity
      results.check = await pgQuery("threat_engine_check",
        `SELECT severity, status, COUNT(*) FROM check_findings
         WHERE scan_run_id=$1 ${provider ? "AND provider=$2" : ""}
         GROUP BY severity, status ORDER BY severity`,
        provider ? [scan_run_id, provider] : [scan_run_id]
      );

      // Threat findings by category
      results.threat = await pgQuery("threat_engine_threat",
        `SELECT threat_category, severity, COUNT(*) FROM threat_findings
         WHERE scan_run_id=$1 ${provider ? "AND provider=$2" : ""}
         GROUP BY threat_category, severity ORDER BY severity LIMIT 10`,
        provider ? [scan_run_id, provider] : [scan_run_id]
      );

      // Compliance score
      results.compliance = await pgQuery("threat_engine_compliance",
        `SELECT compliance_framework, compliance_score, controls_passed, controls_failed
         FROM compliance_report WHERE scan_run_id=$1 LIMIT 5`,
        [scan_run_id]
      );

      // IAM findings count
      results.iam = await pgQuery("threat_engine_iam",
        `SELECT severity, COUNT(*) FROM iam_findings WHERE scan_run_id=$1 GROUP BY severity`,
        [scan_run_id]
      );

      return { content: [{ type: "text", text: JSON.stringify({
        scan_run_id,
        provider,
        discoveries_by_type: results.discoveries.rows,
        check_by_severity: results.check.rows,
        threat_by_category: results.threat.rows,
        compliance: results.compliance.rows,
        iam_by_severity: results.iam.rows,
      }, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Tool: seeding_status ─────────────────────────────────────────────────────

server.tool(
  "seeding_status",
  `Check multi-CSP seeding status: rule_metadata (check rules), resource_security_relationship_rules,
service_classification, compliance_frameworks. Shows what's in DB per CSP vs what's needed.`,
  {
    provider: z.string().optional().describe("Filter by provider: azure, gcp, k8s, oci, ibm, alicloud"),
  },
  async ({ provider }) => {
    try {
      const provFilter = provider ? `WHERE provider=$1` : "";
      const params = provider ? [provider] : [];

      const rules = await pgQuery("threat_engine_check",
        `SELECT provider, COUNT(*) as rule_count FROM rule_metadata ${provFilter} GROUP BY provider ORDER BY provider`,
        params
      );

      const relationships = await pgQuery("threat_engine_inventory",
        `SELECT provider, COUNT(*) as rel_count FROM resource_security_relationship_rules ${provFilter} GROUP BY provider ORDER BY provider`,
        params
      );

      const classification = await pgQuery("threat_engine_inventory",
        `SELECT csp as provider, COUNT(*) as asset_types FROM service_classification ${provider ? "WHERE csp=$1" : ""} GROUP BY csp ORDER BY csp`,
        params
      );

      const frameworks = await pgQuery("threat_engine_compliance",
        `SELECT provider, framework_id, name FROM compliance_frameworks ${provFilter} ORDER BY provider, framework_id`,
        params
      );

      return { content: [{ type: "text", text: JSON.stringify({
        rule_metadata_per_provider: rules.rows,
        relationship_rules_per_provider: relationships.rows,
        asset_classification_per_provider: classification.rows,
        compliance_frameworks: frameworks.rows,
      }, null, 2) }] };
    } catch (e) {
      return { content: [{ type: "text", text: `ERROR: ${e.message}` }], isError: true };
    }
  }
);

// ─── Start ───────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
