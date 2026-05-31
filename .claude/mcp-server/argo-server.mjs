#!/usr/bin/env node
/**
 * Argo Workflows MCP Server
 *
 * Wraps the Argo Workflows REST API so Claude agents can query pipeline status,
 * list recent scan workflows, and fetch step logs without raw bash.
 *
 * Access:
 *   Inside cluster  → ARGO_SERVER=https://argo-server.argo.svc.cluster.local:2746
 *   Local dev       → kubectl port-forward svc/argo-server -n argo 2746:2746
 *                     then ARGO_SERVER=https://localhost:2746
 *
 * Auth:
 *   Set ARGO_TOKEN to a service-account bearer token, or leave empty if
 *   the Argo server is running with --auth-mode=server (no token needed).
 *
 * Tools exposed:
 *   argo_list       — list recent workflows (optionally filter by label/phase)
 *   argo_get        — get full status of a workflow by name
 *   argo_logs       — fetch stdout logs for a specific workflow step/pod
 *   argo_scan_status — find and summarise the pipeline workflow for a scan_run_id
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import https from "https";

const ARGO_SERVER = (process.env.ARGO_SERVER || "https://localhost:2746").replace(/\/$/, "");
const ARGO_NAMESPACE = process.env.ARGO_NAMESPACE || "argo";
const ARGO_TOKEN = process.env.ARGO_TOKEN || "";

// Accept self-signed TLS certs from in-cluster Argo server
const agent = new https.Agent({ rejectUnauthorized: false });

// ─── HTTP helper ─────────────────────────────────────────────────────────────

async function argoGet(path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${ARGO_SERVER}${path}${qs ? "?" + qs : ""}`;
  const headers = { "Content-Type": "application/json" };
  if (ARGO_TOKEN) headers["Authorization"] = `Bearer ${ARGO_TOKEN}`;

  const res = await fetch(url, { headers, agent });
  if (!res.ok) {
    throw new Error(`Argo API ${res.status}: ${await res.text()}`);
  }
  return res.json();
}

// ─── Formatters ──────────────────────────────────────────────────────────────

function fmtWorkflow(wf) {
  const meta = wf.metadata || {};
  const status = wf.status || {};
  const nodes = status.nodes || {};
  const steps = Object.values(nodes)
    .filter(n => n.type === "Pod" || n.type === "Steps")
    .map(n => `  ${n.phase?.padEnd(10)} ${n.displayName || n.id}`)
    .join("\n");
  return [
    `name       : ${meta.name}`,
    `namespace  : ${meta.namespace}`,
    `phase      : ${status.phase}`,
    `started    : ${status.startedAt}`,
    `finished   : ${status.finishedAt || "(running)"}`,
    `message    : ${status.message || ""}`,
    `labels     : ${JSON.stringify(meta.labels || {})}`,
    `steps:\n${steps || "  (none)"}`,
  ].join("\n");
}

function fmtList(items) {
  if (!items?.length) return "(no workflows found)";
  return items
    .map(wf => {
      const s = wf.status || {};
      const m = wf.metadata || {};
      return `${(s.phase || "").padEnd(12)} ${m.name}  started=${s.startedAt || "?"}`;
    })
    .join("\n");
}

// ─── MCP server ──────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "argo",
  version: "1.0.0",
  description: "Argo Workflows — list pipelines, get status, fetch logs",
});

server.tool(
  "argo_list",
  "List recent Argo workflows. Filter by phase (Running/Succeeded/Failed) or a label value.",
  {
    phase: z.string().optional().describe("Filter by phase: Running | Succeeded | Failed | Error"),
    label: z.string().optional().describe("Label selector, e.g. 'scan_run_id=abc123' or 'workflows.argoproj.io/phase=Failed'"),
    limit: z.number().default(20).describe("Max workflows to return"),
  },
  async ({ phase, label, limit }) => {
    const params = { limit };
    if (label) params["listOptions.labelSelector"] = label;
    if (phase) params["fields"] = `items.metadata,items.status.phase,items.status.startedAt,items.status.finishedAt`;

    const data = await argoGet(`/api/v1/workflows/${ARGO_NAMESPACE}`, params);
    const items = (data.items || []).filter(wf => !phase || wf.status?.phase === phase);
    return { content: [{ type: "text", text: fmtList(items) }] };
  }
);

server.tool(
  "argo_get",
  "Get full status and step breakdown for a specific workflow by name.",
  {
    name: z.string().describe("Workflow name, e.g. cspm-pipeline-abc123"),
  },
  async ({ name }) => {
    const data = await argoGet(`/api/v1/workflows/${ARGO_NAMESPACE}/${name}`);
    return { content: [{ type: "text", text: fmtWorkflow(data) }] };
  }
);

server.tool(
  "argo_logs",
  "Fetch stdout logs for a workflow or a specific pod/step within a workflow.",
  {
    workflow: z.string().describe("Workflow name"),
    pod: z.string().optional().describe("Specific pod name within the workflow (leave empty for all pods)"),
    grep: z.string().optional().describe("Filter log lines containing this string"),
    tail: z.number().default(100).describe("Last N lines to return"),
  },
  async ({ workflow, pod, grep, tail }) => {
    const path = pod
      ? `/api/v1/workflows/${ARGO_NAMESPACE}/${workflow}/log?podName=${pod}&logOptions.tailLines=${tail}`
      : `/api/v1/workflows/${ARGO_NAMESPACE}/${workflow}/log?logOptions.tailLines=${tail}`;

    // Argo log endpoint returns newline-delimited JSON
    const headers = { "Content-Type": "application/json" };
    if (ARGO_TOKEN) headers["Authorization"] = `Bearer ${ARGO_TOKEN}`;
    const res = await fetch(`${ARGO_SERVER}${path}`, { headers, agent });
    const text = await res.text();

    let lines = text
      .split("\n")
      .filter(Boolean)
      .map(line => {
        try {
          const obj = JSON.parse(line);
          return `[${obj.result?.podName || "?"}] ${obj.result?.content || line}`;
        } catch {
          return line;
        }
      });

    if (grep) lines = lines.filter(l => l.includes(grep));
    return { content: [{ type: "text", text: lines.join("\n") || "(no log output)" }] };
  }
);

server.tool(
  "argo_scan_status",
  "Find the Argo pipeline workflow for a given scan_run_id and return a summary of each engine step's status.",
  {
    scan_run_id: z.string().describe("The scan_run_id UUID to look up"),
  },
  async ({ scan_run_id }) => {
    // Workflows are labelled with scan_run_id
    const data = await argoGet(`/api/v1/workflows/${ARGO_NAMESPACE}`, {
      "listOptions.labelSelector": `scan_run_id=${scan_run_id}`,
      limit: 5,
    });

    const items = data.items || [];
    if (!items.length) {
      // Try searching by name substring (Argo names often include scan_run_id prefix)
      const all = await argoGet(`/api/v1/workflows/${ARGO_NAMESPACE}`, { limit: 50 });
      const match = (all.items || []).filter(wf =>
        wf.metadata?.name?.includes(scan_run_id.slice(0, 8))
      );
      if (!match.length) return { content: [{ type: "text", text: `No workflow found for scan_run_id=${scan_run_id}` }] };
      return { content: [{ type: "text", text: fmtWorkflow(match[0]) }] };
    }

    return { content: [{ type: "text", text: fmtWorkflow(items[0]) }] };
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);