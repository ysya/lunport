# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS build
WORKDIR /relay
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
COPY scripts ./scripts
RUN node scripts/build-passkey-page.mjs
COPY selfhost/central ./selfhost/central
RUN npx esbuild src/index.ts --bundle --format=esm --platform=browser --external:cloudflare:* --outfile=dist/core/index.js \
    && npx esbuild src/security/selfhost.ts --bundle --format=esm --platform=browser --external:cloudflare:* --outfile=dist/security/index.js \
    && npx esbuild selfhost/central/control.ts --bundle --format=esm --platform=browser --external:cloudflare:* --outfile=dist/control/index.js
RUN case "$(node -p process.arch)" in \
      x64) pkg=workerd-linux-64 ;; arm64) pkg=workerd-linux-arm64 ;; *) exit 1 ;; \
    esac && cp "node_modules/@cloudflare/$pkg/bin/workerd" /relay/workerd

# App updates can replace only this module artifact. It has no network, security volume or secrets.
FROM debian:bookworm-slim AS core-bundle
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin relay \
    && mkdir /modules && chown relay:relay /modules
COPY --from=build /relay/dist/core/index.js /artifact/index.js
COPY selfhost/central/export-core.sh /usr/local/bin/export-core
USER relay
ENTRYPOINT ["/bin/sh", "/usr/local/bin/export-core"]

# Review/update this image separately from application releases.
FROM debian:bookworm-slim AS security-runtime
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin relay \
    && mkdir /data /security-data && chown relay:relay /data /security-data
COPY --from=build /relay/workerd /usr/local/bin/workerd
COPY --from=build /relay/dist/security/index.js /relay/security/index.js
COPY --from=build /relay/dist/control/index.js /relay/control/index.js
COPY selfhost/central/services.capnp.in selfhost/central/runtime.capnp selfhost/central/control.capnp /relay/
COPY selfhost/central/entrypoint.sh selfhost/central/healthcheck.sh /relay/
USER relay
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/relay/entrypoint.sh"]
