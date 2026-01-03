FROM node:18-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js data.json ./

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
