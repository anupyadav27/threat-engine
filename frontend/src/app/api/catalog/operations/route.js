import fs from 'fs';
import path from 'path';
import { NextResponse } from 'next/server';

const CATALOG_BASE =
  process.env.CATALOG_PATH ||
  '/Users/apple/Desktop/threat-engine/catalog/discovery_generator';

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const csp = searchParams.get('csp');
  const service = searchParams.get('service');
  if (!csp || !service) {
    return NextResponse.json({ error: 'csp and service required' }, { status: 400 });
  }

  const regPath = path.join(CATALOG_BASE, csp, service, 'step2_read_operation_registry.json');
  if (!fs.existsSync(regPath)) {
    return NextResponse.json({ operations: {}, total: 0 });
  }

  try {
    const raw = fs.readFileSync(regPath, 'utf-8');
    const data = JSON.parse(raw);
    return NextResponse.json({
      operations: data.operations || {},
      total: data.total_operations || 0,
      independent_count: data.independent_count || 0,
      dependent_count: data.dependent_count || 0,
    });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
