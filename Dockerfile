FROM node:20-bookworm-slim

# Install Lua 5.1 (luac required by IronBrew2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    lua5.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=10000

EXPOSE 10000

CMD ["node", "server.js"]
