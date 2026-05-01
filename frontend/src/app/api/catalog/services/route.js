import fs from 'fs';
import path from 'path';
import { NextResponse } from 'next/server';

const CATALOG_BASE =
  process.env.CATALOG_PATH ||
  '/Users/apple/Desktop/threat-engine/catalog/discovery_generator';

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const csp = searchParams.get('csp');
  if (!csp) return NextResponse.json({ error: 'csp required' }, { status: 400 });

  const cspPath = path.join(CATALOG_BASE, csp);
  if (!fs.existsSync(cspPath)) {
    return NextResponse.json({ error: `CSP not found: ${csp}` }, { status: 404 });
  }

  try {
    const services = fs
      .readdirSync(cspPath, { withFileTypes: true })
      .filter((d) => d.isDirectory() && !d.name.startsWith('.'))
      .map((d) => d.name)
      .sort();
    return NextResponse.json({ services });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
