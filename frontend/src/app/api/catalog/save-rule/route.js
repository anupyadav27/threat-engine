import { NextResponse } from 'next/server';

// Rule engine base URL — via NLB in prod, direct in local dev
const RULE_ENGINE_URL =
  process.env.RULE_ENGINE_URL ||
  (process.env.NEXT_PUBLIC_GATEWAY_URL
    ? `${process.env.NEXT_PUBLIC_GATEWAY_URL}/rule`
    : 'http://localhost:8011');

async function callRuleEngine(path, body) {
  const res = await fetch(`${RULE_ENGINE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Rule engine error ${res.status}`);
  }
  return data;
}

export async function POST(request) {
  try {
    const body = await request.json();
    const { checkDuplicate, provider, service, for_each, tenant_id } = body;

    // ── Duplicate check ────────────────────────────────────────────────────
    if (checkDuplicate) {
      const result = await callRuleEngine('/api/v1/user-rules/check-duplicate', {
        service,
        provider,
        for_each,
        tenant_id: tenant_id || null,
      });
      return NextResponse.json(result);
    }

    // ── Save rule ──────────────────────────────────────────────────────────
    const {
      rule_id, severity, category, title, description, frameworks,
      conditions, condition_logic,
      discovery_id, discovery_action, discovery_items_for, discovery_item_fields,
      customer_id,
    } = body;

    const result = await callRuleEngine('/api/v1/user-rules', {
      rule_id,
      service,
      provider,
      severity,
      category,
      title,
      description,
      for_each,
      conditions,
      condition_logic,
      frameworks,
      discovery_id,
      discovery_action,
      discovery_items_for,
      discovery_item_fields,
      tenant_id: tenant_id || null,
      customer_id: customer_id || null,
    });

    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
