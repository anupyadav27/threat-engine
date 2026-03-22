# Payload Library

Payload collection for DAST vulnerability testing, downloaded from **GitHub SecLists** repository.

## 📁 Structure

```
payloads/
├── sqli/                  # SQL Injection (78 payloads)
│   ├── error_based.txt    # 47 error-based SQLi
│   ├── blind.txt          # 16 blind SQLi
│   └── time_based.txt     # 15 time-based SQLi
│
├── xss/                   # Cross-Site Scripting (90 payloads)
│   ├── basic.txt          # 38 basic XSS
│   ├── filter_bypass.txt  # 33 filter bypass
│   └── dom.txt            # 19 DOM XSS
│
├── command_injection/     # OS Command Injection (93 payloads)
│   ├── unix.txt           # 92 Unix/Linux commands
│   └── windows.txt        # 1 Windows command
│
├── path_traversal/        # Directory Traversal (141 payloads)
│   ├── unix.txt           # 100 Unix paths
│   └── windows.txt        # 41 Windows paths
│
├── ssrf/                  # Server-Side Request Forgery (24 payloads)
│   ├── localhost.txt      # 16 localhost variants
│   └── cloud_metadata.txt # 8 cloud metadata endpoints
│
├── nosql/                 # NoSQL Injection (10 payloads)
│   └── mongodb.txt        # 10 MongoDB injections
│
├── xxe/                   # XML External Entity (4 payloads)
│   └── basic.txt          # 4 XXE payloads
│
├── ssti/                  # Server-Side Template Injection (8 payloads)
│   └── jinja2.txt         # 8 Jinja2 SSTI
│
└── fuzzing/               # General Fuzzing (31 payloads)
    └── special_chars.txt  # 31 special characters
```

**Total: 479 payloads across 9 vulnerability categories**

## 🎯 Payload Source

All payloads are downloaded directly from:

**SecLists** - https://github.com/danielmiessler/SecLists
- Industry-standard payload collection
- MIT License
- Used by professional pentesters worldwide
- Regularly updated and maintained

## 📊 Payload Organization

Payloads are organized using the automated download script:

```bash
bash scripts/download_and_organize_payloads.sh
```

The script:
- ✅ Clones SecLists from GitHub
- ✅ Extracts top 50-100 payloads per category
- ✅ Cleans and deduplicates entries
- ✅ Organizes into vulnerability categories
- ✅ Creates backup before updating
- ✅ Maintains metadata tracking

## 🔧 Usage

```python
from payloads import PayloadLoader

# Load specific category
loader = PayloadLoader()
sqli_payloads = loader.load_category('sqli')

# Load with filtering
basic_xss = loader.load_payloads('xss', subcategory='basic')

# Get encoded variants
encoder = PayloadEncoder()
encoded = encoder.url_encode("<script>alert(1)</script>")
```

## 📝 Payload Categories

| Category | Description | Payload Count |
|----------|-------------|---------------|
| **sqli** | SQL Injection (error, blind, time-based) | ~80 |
| **xss** | Cross-Site Scripting (reflected, DOM, stored) | ~100 |
| **command_injection** | OS Command Injection (Unix/Windows) | ~60 |
| **path_traversal** | Directory Traversal / LFI | ~50 |
| **xxe** | XML External Entity | ~20 |
| **ssrf** | Server-Side Request Forgery | ~40 |
| **nosql** | NoSQL Injection (MongoDB, etc.) | ~30 |
| **ssti** | Template Injection (Jinja2, Twig, etc.) | ~40 |
| **fuzzing** | General fuzzing strings | ~100 |

## 🔄 Updating Payloads

To add custom payloads:

1. Add to appropriate category file (e.g., `sqli/custom.txt`)
2. Follow format: one payload per line
3. Comment lines start with `#`

To update from sources:

```bash
# Optional: Download full SecLists
bash scripts/download_seclists.sh
```

## ⚖️ License

Payloads are derived from open-source security research:
- SecLists: MIT License
- PayloadsAllTheThings: MIT License

Always ensure you have proper authorization before testing.
