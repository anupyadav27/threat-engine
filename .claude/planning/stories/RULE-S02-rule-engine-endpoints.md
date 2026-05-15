# RULE-S02 — Rule Engine: Suppression CRUD Endpoints

**Engine**: rule engine (`engines/rule/api_server.py`, port 8011)  
**Status**: Ready for dev

## Goal
Add three endpoints to the rule engine for creating, listing, and removing suppressions stored in the check DB.

## Endpoints
- `POST /api/v1/rules/suppress` — create a suppression (tenant-wide or account-level)
- `GET /api/v1/rules/suppressions` — list all active suppressions for authenticated tenant
- `DELETE /api/v1/rules/suppressions/{suppression_id}` — lift (remove) a suppression

## Acceptance Criteria
- [ ] Tenant_id read from X-Auth-Context header (never from request body)
- [ ] account_id validated: if provided, must belong to the authenticated tenant
- [ ] scope_type validated: enum of rule | service | technology | provider
- [ ] Expired suppressions excluded from GET list
- [ ] DELETE returns 404 if suppression_id not found for this tenant
