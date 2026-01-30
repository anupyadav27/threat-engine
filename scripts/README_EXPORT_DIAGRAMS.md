# Export Database ER Diagrams

This script exports all database ER diagrams to PNG or SVG images.

## Quick Start

### Option 1: Using mermaid-cli (Recommended - Faster)

1. Install mermaid-cli:
```bash
npm install -g @mermaid-js/mermaid-cli
```

2. Run the export script:
```bash
python scripts/export_database_diagrams.py
```

### Option 2: Using Playwright (Fallback)

1. Install Playwright:
```bash
pip install playwright
playwright install chromium
```

2. Run the export script:
```bash
python scripts/export_database_diagrams.py
```

## Usage

### Export all diagrams as PNG (default):
```bash
python scripts/export_database_diagrams.py
```

### Export as SVG:
```bash
python scripts/export_database_diagrams.py --format svg
```

### Export to custom directory:
```bash
python scripts/export_database_diagrams.py --output docs/images
```

### Export specific diagram only:
```bash
python scripts/export_database_diagrams.py --diagram dynamodb
python scripts/export_database_diagrams.py --diagram configscan
python scripts/export_database_diagrams.py --diagram compliance
python scripts/export_database_diagrams.py --diagram inventory
python scripts/export_database_diagrams.py --diagram admin
python scripts/export_database_diagrams.py --diagram dataflow
```

## Output

Diagrams are exported to `docs/database_diagrams/` by default:
- `dynamodb.png` / `dynamodb.svg`
- `configscan.png` / `configscan.svg`
- `compliance.png` / `compliance.svg`
- `inventory.png` / `inventory.svg`
- `admin.png` / `admin.svg`
- `dataflow.png` / `dataflow.svg`

## Requirements

- Python 3.7+
- Either:
  - Node.js + mermaid-cli (`npm install -g @mermaid-js/mermaid-cli`)
  - OR Python Playwright (`pip install playwright && playwright install chromium`)

## Troubleshooting

### mermaid-cli not found
Install it: `npm install -g @mermaid-js/mermaid-cli`

### Playwright not installed
Install it: `pip install playwright && playwright install chromium`

### Diagrams not rendering correctly
- Try using mermaid-cli instead of Playwright
- Check that the diagram syntax is valid
- Increase timeout values in the script if needed
