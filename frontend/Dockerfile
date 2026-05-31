ARG NODE_VERSION=22-alpine

# ── deps ────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS deps
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# ── catalog extractor ────────────────────────────────────────────────
# Only pulls step2_read_operation_registry.json files (~61 MB) from the
# 1.4 GB discovery_generator_data tree.  Preserves CSP/service structure.
FROM alpine:3.19 AS catalog-extractor
COPY catalog/discovery_generator_data /catalog
RUN mkdir -p /catalog-slim && \
    find /catalog -mindepth 3 -maxdepth 3 -name "step2_read_operation_registry.json" | \
    while read f; do \
        rel="${f#/catalog/}"; \
        target_dir="/catalog-slim/$(dirname "$rel")"; \
        mkdir -p "$target_dir"; \
        cp "$f" "$target_dir/"; \
    done

# ── builder ─────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY frontend/ .

# Bake env at build time (NEXT_PUBLIC_* are client-visible, safe to embed)
# Default is empty string = relative URLs (works in-cluster via nginx ingress routing).
# Override at build time: docker build --build-arg NEXT_PUBLIC_API_BASE=http://NLB_URL .
ARG NEXT_PUBLIC_API_BASE=
ARG NEXT_PUBLIC_AUTH_URL=
ARG NEXT_PUBLIC_TENANT_ID=default-tenant
ARG NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=

ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}
ENV NEXT_PUBLIC_AUTH_URL=${NEXT_PUBLIC_AUTH_URL}
ENV NEXT_PUBLIC_TENANT_ID=${NEXT_PUBLIC_TENANT_ID}
ENV NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=${NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY}

# Guard: DEV_BYPASS_AUTH must never be true in a production image
RUN ! grep -r "NEXT_PUBLIC_DEV_BYPASS_AUTH=true" /app/.env* 2>/dev/null || \
    (echo "ERROR: NEXT_PUBLIC_DEV_BYPASS_AUTH must not be true in production" && exit 1)

RUN npm run build

# ── runner ──────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
# Slim catalog: only step2 registry JSONs needed by /api/catalog/* routes
COPY --from=catalog-extractor /catalog-slim ./catalog

EXPOSE 3000
CMD ["node", "server.js"]
