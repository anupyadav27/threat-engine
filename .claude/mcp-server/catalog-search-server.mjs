/**
 * Catalog Search MCP Server
 * Exposes grep-based search over catalog/rule/ and catalog/discovery_generator_data/
 * as an MCP tool so agents can call it directly without raw bash.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "../../..");
const CATALOG_SEARCH = path.join(__dirname, "../scripts/catalog_search.py");

const server = new Server(
  { name: "catalog-search", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "catalog_search",
      description: "Search the CSPM rule catalog (catalog/rule/) and discovery data (catalog/discovery_generator_data/) by keyword. Returns matching rule files with rule_id, title, CSP, and file path.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search term (regex supported)" },
          csp: { type: "string", enum: ["aws", "azure", "gcp", "oci", "alicloud", "ibm"], description: "Filter by cloud provider (optional)" },
          type: { type: "string", enum: ["rule", "discovery", "all"], default: "all", description: "Search rules, discovery YAMLs, or both" },
          limit: { type: "number", default: 20, description: "Max results to return" },
        },
        required: ["query"],
      },
    },
    {
      name: "catalog_count",
      description: "Count rules in the catalog by CSP or service. Useful to understand rule coverage.",
      inputSchema: {
        type: "object",
        properties: {
          csp: { type: "string", enum: ["aws", "azure", "gcp", "oci", "alicloud", "ibm"], description: "Cloud provider to count rules for (optional, counts all if omitted)" },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  if (name === "catalog_search") {
    const { query, csp, type = "all", limit = 20 } = args;
    const cspFlag = csp ? `--csp ${csp}` : "";
    const typeFlag = `--type ${type}`;
    const cmd = `python3 "${CATALOG_SEARCH}" ${JSON.stringify(query)} ${cspFlag} ${typeFlag} --limit ${limit} --json`;
    try {
      const out = execSync(cmd, { cwd: REPO_ROOT, timeout: 15000 }).toString();
      const results = JSON.parse(out);
      return {
        content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${e.message}\nstderr: ${e.stderr?.toString() || ""}` }],
        isError: true,
      };
    }
  }

  if (name === "catalog_count") {
    const { csp } = args;
    try {
      const globPath = csp
        ? `${REPO_ROOT}/catalog/rule/${csp}_rule_check/**/*.yaml`
        : `${REPO_ROOT}/catalog/rule/**/*.yaml`;
      const out = execSync(`find "${REPO_ROOT}/catalog/rule" -name "*.yaml" ${csp ? `-path "*/${csp}_rule_check/*"` : ""} | wc -l`, { timeout: 10000 }).toString().trim();
      return {
        content: [{ type: "text", text: `${out} rule YAML files${csp ? ` for ${csp}` : " total"}` }],
      };
    } catch (e) {
      return {
        content: [{ type: "text", text: `Error: ${e.message}` }],
        isError: true,
      };
    }
  }

  return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
});

const transport = new StdioServerTransport();
await server.connect(transport);