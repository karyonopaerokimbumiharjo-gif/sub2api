FROM node:24-alpine
WORKDIR /app/runtime/pi
COPY runtime/pi/package.json runtime/pi/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY runtime/pi/native.mjs runtime/pi/server.mjs ./
COPY tools/pi-integration/response-observer.mjs tools/pi-integration/acceptance.mjs /app/tools/pi-integration/
ENV HOST=0.0.0.0 PORT=8091
USER node
CMD ["node","server.mjs"]
