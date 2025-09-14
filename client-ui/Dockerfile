FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --silent || npm i --silent
COPY . .
# Build-time args provided from docker-compose (via .env)
ARG VITE_ISSUER
ARG VITE_CLIENT_ID
ARG VITE_SCOPE
ARG VITE_REDIRECT_URI
ARG VITE_RS_BASE
ENV VITE_ISSUER=$VITE_ISSUER
ENV VITE_CLIENT_ID=$VITE_CLIENT_ID
ENV VITE_SCOPE=$VITE_SCOPE
ENV VITE_REDIRECT_URI=$VITE_REDIRECT_URI
ENV VITE_RS_BASE=$VITE_RS_BASE
RUN npm run build
FROM node:20-alpine
WORKDIR /app
COPY --from=build /app /app
EXPOSE 5174
CMD ["npm","run","preview","--","--host","0.0.0.0","--port","5174"]
