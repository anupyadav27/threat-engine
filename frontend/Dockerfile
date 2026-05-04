ARG NODE_VERSION=22-alpine

# ── deps ────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS deps
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

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

EXPOSE 3000
CMD ["node", "server.js"]
