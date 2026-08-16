# node-redis — the fifth client of recon item 2.
FROM node:22-alpine
WORKDIR /app
RUN npm install --no-fund --no-audit redis@4.7.0
COPY app.js /app/
ENTRYPOINT ["node", "/app/app.js"]
