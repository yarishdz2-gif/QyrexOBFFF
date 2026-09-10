FROM node:20-bookworm-slim

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends lua5.1 lua5.4 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/lua5.1 /usr/local/bin/lua5.1 \
 && ln -sf /usr/bin/luac5.1 /usr/local/bin/luac5.1 \
 && ln -sf /usr/bin/lua5.4 /usr/local/bin/lua5.4 \
 && (test -f /usr/bin/luac5.4 && ln -sf /usr/bin/luac5.4 /usr/local/bin/luac5.4 || true) \
 && ln -sf /usr/bin/lua5.1 /usr/local/bin/lua \
 && ln -sf /usr/bin/luac5.1 /usr/local/bin/luac

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js obfuscate.js worker.js index.html ./

# Pre-extract engines at BUILD time → zero runtime tar/base64 cost, stable path
ENV QYREX_ENGINES=/app/engines
RUN mkdir -p /app/engines /app/jobs \
 && node -e "require('./obfuscate').getRoot(); console.log('[build] engines at', require('./obfuscate').getRoot())" \
 && test -f /app/engines/Prometheus-master/cli.lua \
 && chmod -R a+rX /app/engines \
 && chmod 777 /app/jobs

ENV NODE_ENV=production
ENV PORT=10000
ENV NODE_OPTIONS=--max-old-space-size=768
ENV PATH="/usr/local/bin:/usr/bin:${PATH}"

EXPOSE 10000

CMD ["sh", "-c", "mkdir -p /app/jobs && echo [QyrexOBF] lua=$(which lua5.1) engines=$QYREX_ENGINES && lua5.1 -v && node server.js"]
