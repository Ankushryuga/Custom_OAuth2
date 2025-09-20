#FROM node:20-alpine AS ui
#WORKDIR /ui
#COPY login-ui/package.json login-ui/package-lock.json* ./
#RUN npm ci --silent || npm i --silent
#COPY login-ui .
#RUN npm run build
#
#FROM maven:3.9.9-eclipse-temurin-21 AS build
#WORKDIR /workspace
#COPY pom.xml .
#COPY src ./src
#RUN mkdir -p /workspace/src/main/resources/static/login
#COPY --from=ui /ui/dist/ /workspace/src/main/resources/static/login/
#RUN mvn -q -B -DskipTests package
#
#FROM eclipse-temurin:21-jre
#WORKDIR /app
#COPY --from=build /workspace/target/auth-server-*.jar app.jar
#EXPOSE 8080
#ENTRYPOINT ["java","-jar","/app/app.jar"]

# ---- Build the login UI ----
FROM node:20-alpine AS ui
WORKDIR /ui
COPY login-ui/package.json login-ui/package-lock.json* ./

# Remove package-lock.json and node_modules
RUN rm -rf login-ui/node_modules login-ui/package-lock.json
RUN npm ci --include=dev
# RUN npm ci --silent || npm i --silent
COPY login-ui .
RUN npm run build

# ---- Build Spring Boot app ----
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
# Copy built UI into static/login (served at /login)
RUN mkdir -p src/main/resources/static/login
COPY --from=ui /ui/dist/ src/main/resources/static/login/
RUN mvn -q -B -DskipTests package

# ---- Runtime image ----
FROM eclipse-temurin:21-jre
WORKDIR /app
ENV JAVA_TOOL_OPTIONS="-Xms256m -Xmx512m"
COPY --from=build /workspace/target/*.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
