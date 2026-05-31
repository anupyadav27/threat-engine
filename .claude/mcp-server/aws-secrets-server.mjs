#!/usr/bin/env node
/**
 * AWS Secrets Manager MCP Server
 *
 * Resolves secret values from AWS Secrets Manager so Claude agents can look up
 * DB passwords, API keys, and engine credentials without `kubectl exec` workarounds.
 *
 * Auth: uses the default AWS credential provider chain —
 *   1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars
 *   2. ~/.aws/credentials (profile set by AWS_PROFILE)
 *   3. EKS IRSA / EC2 instance role (when running in-cluster)
 *
 * READ-ONLY. No create/update/delete operations.
 *
 * Tools exposed:
 *   list_secrets    — list secrets under a prefix (default: threat-engine/)
 *   get_secret      — resolve a secret's value by full name or partial match
 *   describe_secret — metadata only (name, ARN, rotation status) — no value exposed
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  SecretsManagerClient,
  ListSecretsCommand,
  GetSecretValueCommand,
  DescribeSecretCommand,
} from "@aws-sdk/client-secrets-manager";
import { z } from "zod";

const REGION = process.env.AWS_REGION || "ap-south-1";
const DEFAULT_PREFIX = "threat-engine/";

const client = new SecretsManagerClient({ region: REGION });

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function listSecrets(prefix) {
  const results = [];
  let token;
  do {
    const cmd = new ListSecretsCommand({
      Filters: prefix ? [{ Key: "name", Values: [prefix] }] : undefined,
      NextToken: token,
      MaxResults: 100,
    });
    const res = await client.send(cmd);
    results.push(...(res.SecretList || []));
    token = res.NextToken;
  } while (token);
  return results;
}

function redactValue(value) {
  if (!value) return "(empty)";
  if (value.length <= 6) return "***";
  return value.slice(0, 3) + "***" + value.slice(-3);
}

function parseSecretJson(raw) {
  try {
    const obj = JSON.parse(raw);
    // Redact values but show keys so agents know what fields are present
    return Object.entries(obj)
      .map(([k, v]) => `  ${k}: ${redactValue(String(v))}`)
      .join("\n");
  } catch {
    return redactValue(raw);
  }
}

// ─── MCP server ──────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "aws-secrets",
  version: "1.0.0",
  description: "AWS Secrets Manager — list and resolve engine secrets (read-only)",
});

server.tool(
  "list_secrets",
  "List secrets in AWS Secrets Manager. Defaults to the threat-engine/ prefix.",
  {
    prefix: z.string().default(DEFAULT_PREFIX).describe("Name prefix to filter by, e.g. 'threat-engine/' or 'threat-engine/account/'"),
    show_arn: z.boolean().default(false).describe("Include ARNs in output"),
  },
  async ({ prefix, show_arn }) => {
    const secrets = await listSecrets(prefix);
    if (!secrets.length) {
      return { content: [{ type: "text", text: `No secrets found under prefix: ${prefix}` }] };
    }
    const lines = secrets.map(s => {
      const parts = [s.Name];
      if (show_arn) parts.push(`  arn=${s.ARN}`);
      if (s.RotationEnabled) parts.push("  [rotation=on]");
      if (s.LastChangedDate) parts.push(`  last_changed=${s.LastChangedDate.toISOString().slice(0, 10)}`);
      return parts.join("");
    });
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "get_secret",
  "Retrieve a secret's value from AWS Secrets Manager. JSON secrets show field names with redacted values; string secrets are partially redacted. Use this to confirm a secret exists and what keys it contains — not to read the raw password.",
  {
    name: z.string().describe("Full secret name (e.g. 'threat-engine/account/588989875114') or partial match"),
    show_keys_only: z.boolean().default(true).describe("If true (default), show JSON keys with redacted values. If false, return raw value (use with caution)."),
  },
  async ({ name, show_keys_only }) => {
    // If partial name, search first
    let secretName = name;
    if (!name.startsWith("arn:") && !name.includes("/")) {
      const all = await listSecrets(DEFAULT_PREFIX);
      const match = all.find(s => s.Name.includes(name));
      if (!match) return { content: [{ type: "text", text: `Secret not found matching: ${name}` }] };
      secretName = match.Name;
    }

    const cmd = new GetSecretValueCommand({ SecretId: secretName });
    const res = await client.send(cmd);
    const raw = res.SecretString || Buffer.from(res.SecretBinary || "", "base64").toString();

    const display = show_keys_only ? parseSecretJson(raw) : raw;
    return {
      content: [{
        type: "text",
        text: `Secret: ${secretName}\nARN: ${res.ARN}\nVersion: ${res.VersionId}\n\n${display}`,
      }],
    };
  }
);

server.tool(
  "describe_secret",
  "Get metadata for a secret (name, ARN, rotation config, tags) without exposing the value.",
  {
    name: z.string().describe("Full or partial secret name"),
  },
  async ({ name }) => {
    const cmd = new DescribeSecretCommand({ SecretId: name });
    const res = await client.send(cmd);
    const lines = [
      `Name             : ${res.Name}`,
      `ARN              : ${res.ARN}`,
      `Description      : ${res.Description || ""}`,
      `Rotation enabled : ${res.RotationEnabled || false}`,
      `Rotation lambda  : ${res.RotationLambdaARN || "(none)"}`,
      `Last rotated     : ${res.LastRotatedDate?.toISOString() || "(never)"}`,
      `Last changed     : ${res.LastChangedDate?.toISOString() || "(unknown)"}`,
      `Tags             : ${JSON.stringify(res.Tags || [])}`,
    ];
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);