FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --silent || npm i --silent
COPY . .
RUN npm run build
FROM node:20-alpine
WORKDIR /app
COPY --from=build /app /app
EXPOSE 5173
CMD ["npm","run","preview","--","--host","0.0.0.0","--port","5173"]
