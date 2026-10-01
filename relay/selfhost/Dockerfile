# syntax=docker/dockerfile:1
# Self-hosted SSHelter relay: the bundle `wrangler deploy` uploads to Cloudflare, run by workerd
# (Cloudflare's open-source Workers runtime) with Durable Object storage on a volume.
# Build context: relay/ (compose.yaml sets it). See ../README.md, "Self-host with Docker Compose".

FROM node:22-bookworm-slim AS build
WORKDIR /relay
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY wrangler.jsonc tsconfig.json ./
COPY src ./src
COPY selfhost/workerd.capnp selfhost/check-config.mjs ./selfhost/
RUN node selfhost/check-config.mjs
RUN WRANGLER_SEND_METRICS=false npx wrangler deploy --dry-run --outdir dist
# The workerd binary npm installed for this platform: the same version the relay's tests run on.
RUN case "$(node -p process.arch)" in \
      x64) pkg=workerd-linux-64 ;; \
      arm64) pkg=workerd-linux-arm64 ;; \
      *) echo "unsupported architecture: $(node -p process.arch)" >&2; exit 1 ;; \
    esac \
    && cp "node_modules/@cloudflare/$pkg/bin/workerd" /relay/workerd

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin relay \
    && mkdir /data && chown relay:relay /data
COPY --from=build /relay/workerd /usr/local/bin/workerd
COPY --from=build /relay/dist/index.js /relay/dist/index.js
COPY --from=build /relay/selfhost/workerd.capnp /relay/workerd.capnp
USER relay
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/workerd", "serve", "/relay/workerd.capnp"]
