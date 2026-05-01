#!/bin/bash
# Local dev server for preview — proxies auth to port-forwarded cspm-backend,
# and engine APIs to port-forwarded api-gateway.
export CSPM_BACKEND_URL=http://localhost:8009
export NEXT_PUBLIC_GATEWAY_URL=http://localhost:8000
exec npm --prefix /Users/apple/Desktop/threat-engine/frontend run dev
