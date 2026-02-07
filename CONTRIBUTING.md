# Contributing

Guidelines for contributing to the CSPM Threat Engine platform.

---

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code |
| `dev` | Development integration |
| `feature/*` | New features |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation changes |

### Workflow

1. Create a feature branch from `dev`
2. Make changes with descriptive commits
3. Push branch and create a Pull Request to `dev`
4. Get code review approval
5. Merge to `dev`
6. Periodic merges from `dev` to `main` for releases

---

## Code Standards

### Python Style
- Python 3.11+
- Follow PEP 8
- Use type hints for function signatures
- Docstrings for all public functions/classes
- Max line length: 120 characters

### Naming Conventions
- Variables/functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Files: `snake_case.py`
- Database tables: `snake_case` (e.g., `threat_detections`)
- API paths: `kebab-case` (e.g., `/data-security/scan`)

### Project Structure
Each engine follows the standard layout:
```
engine_name/
├── api_server.py        # FastAPI application
├── database/            # DB connections and queries
├── schemas/             # Pydantic models
├── storage/             # DB writers
├── requirements.txt     # Dependencies
├── Dockerfile           # Container definition
└── README.md            # Engine documentation
```

---

## Commit Messages

Format: `<type>: <description>`

| Type | Usage |
|------|-------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `refactor` | Code refactoring |
| `test` | Adding/updating tests |
| `chore` | Build, CI, deps |
| `perf` | Performance improvement |

Examples:
```
feat: add blast radius computation to threat analyzer
fix: resolve FastAPI route conflict for analysis endpoints
docs: add per-engine API reference documentation
refactor: extract MITRE scoring into separate module
```

---

## Adding a New Engine

1. Create directory: `engine_newengine/`
2. Add `api_server.py` with FastAPI app
3. Add `requirements.txt`
4. Add `Dockerfile`
5. Add `README.md`
6. Register in API Gateway (`api_gateway/main.py`)
7. Create database schema in `consolidated_services/database/schemas/`
8. Add K8s deployment YAML in `kubernetes/` or `deployment/aws/eks/`
9. Add API documentation in `docs/api/`
10. Add tests in `tests/`

---

## Adding New API Endpoints

1. Add route in the engine's `api_server.py`
2. Add Pydantic models in `schemas/`
3. Add database functions in `storage/`
4. Update API documentation in `docs/api/`
5. Add tests
6. If wildcard routes exist, ensure specific routes are registered FIRST

---

## Database Changes

1. Create migration file in `consolidated_services/database/migrations/`
2. Number sequentially (e.g., `011_add_new_column.sql`)
3. Include both UP and DOWN migrations
4. Test on local database first
5. Update `docs/DATABASE_SCHEMA.md`

---

## Testing Requirements

- All new features must have tests
- Unit tests for business logic
- Integration tests for database operations
- Run full test suite before submitting PR: `python -m pytest tests/ -v`
