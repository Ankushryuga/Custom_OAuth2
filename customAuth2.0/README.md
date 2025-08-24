<h3 align="center"> Hi there 👋, thank you for visiting this repo</h3>

<p align="center"> This repo is just POC of OAuth2.0 server using Java Spring Boot and will be using this OAuth2.0 for all of my application</p>

<p align="center"> If you find this repo helpful, please give me a star </p>

# OAuth2 Custom (Spring Boot)

## Services
- Authorization Server: http://localhost:9000
- Resource Server:     http://localhost:8082
- Client App:          http://localhost:8091

## Start Postgres
docker compose up -d

## Build & Run
mvn -q -DskipTests package

# Terminal 1
cd authorization-server && mvn spring-boot:run
# Terminal 2
cd resource-server && mvn spring-boot:run
# Terminal 3
cd client-app && mvn spring-boot:run

## Login (seed user)
username: admin
password: admin123

## Try the flow
1) Open http://localhost:8081  (Client App) -> Login with AS
2) Click "Call Resource" -> RS returns protected data
