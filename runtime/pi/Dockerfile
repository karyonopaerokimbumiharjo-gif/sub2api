FROM node:24-alpine
WORKDIR /app/runtime/pi
COPY runtime/pi/package.json runtime/pi/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY runtime/pi/native.mjs runtime/pi/server.mjs runtime/pi/healthcheck.mjs ./
COPY tools/pi-integration/response-observer.mjs tools/pi-integration/acceptance.mjs /app/tools/pi-integration/
ENV HOST=0.0.0.0 PORT=8091
USER node
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 CMD ["node", "healthcheck.mjs"]
CMD ["node","server.mjs"]
