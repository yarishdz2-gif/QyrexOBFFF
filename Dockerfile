FROM node:20-bookworm-slim

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends lua5.1 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/lua5.1 /usr/local/bin/lua5.1 \
 && ln -sf /usr/bin/luac5.1 /usr/local/bin/luac5.1 \
 && ln -sf /usr/bin/lua5.1 /usr/local/bin/lua \
 && ln -sf /usr/bin/luac5.1 /usr/local/bin/luac \
 && lua5.1 -v \
 && luac5.1 -v \
 && which lua5.1

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js obfuscate.js index.html ./

ENV NODE_ENV=production
ENV PORT=10000
ENV PATH="/usr/local/bin:/usr/bin:${PATH}"

EXPOSE 10000

CMD ["sh", "-c", "echo [QyrexOBF] lua=$(which lua5.1) && lua5.1 -v && node server.js"]
