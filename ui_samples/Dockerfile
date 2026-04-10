ARG NODE_VERSION=22-alpine

# ── deps ────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS deps
WORKDIR /app
COPY ui_samples/package.json ui_samples/package-lock.json ./
RUN npm ci

# ── builder ─────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY ui_samples/ .

# Bake env at build time (NEXT_PUBLIC_* are client-visible, safe to embed)
ARG NEXT_PUBLIC_API_BASE=http://a6fff2656f8c845e5a2d8effc1b3e56f-1461670384.ap-south-1.elb.amazonaws.com
ARG NEXT_PUBLIC_AUTH_URL=http://a6fff2656f8c845e5a2d8effc1b3e56f-1461670384.ap-south-1.elb.amazonaws.com/cspm
ARG NEXT_PUBLIC_TENANT_ID=default-tenant

ENV NEXT_PUBLIC_API_BASE=${NEXT_PUBLIC_API_BASE}
ENV NEXT_PUBLIC_AUTH_URL=${NEXT_PUBLIC_AUTH_URL}
ENV NEXT_PUBLIC_TENANT_ID=${NEXT_PUBLIC_TENANT_ID}

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
