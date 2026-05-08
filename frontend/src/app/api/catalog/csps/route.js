import fs from 'fs';
import path from 'path';
import { NextResponse } from 'next/server';

const CATALOG_BASE =
  process.env.CATALOG_PATH ||
  '/Users/apple/Desktop/threat-engine/catalog/discovery_generator';

const SKIP_DIRS = new Set(['scripts', 'step4a_outputs', 'backup', '__pycache__']);

export async function GET() {
  try {
    if (!fs.existsSync(CATALOG_BASE)) {
      return NextResponse.json({ csps: [] });
    }
    const csps = fs
      .readdirSync(CATALOG_BASE, { withFileTypes: true })
      .filter((d) => d.isDirectory() && !d.name.startsWith('.') && !SKIP_DIRS.has(d.name))
      .map((d) => d.name)
      .sort();
    return NextResponse.json({ csps });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
