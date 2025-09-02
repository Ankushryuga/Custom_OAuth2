<h3 align="center"> Hi there 👋, thank you for visiting this repo</h3>

<p align="center"> This repo is just POC of OAuth2.0 server using Java Spring Boot and will be using this OAuth2.0 for all of my application</p>

<p align="center"> If you find this repo helpful, please give this repo a star </p>


**Minimum requirement to run this**
1. JVM         -- installed
2. MVN         -- installed
3. postgreSQL  -- installed

NOTE: Change the database information in `AuthorizationServer/resources/application.yml` file


# Custom OAuth2.0 Starter (fully fixed)

**Stack:** Spring Boot 3.3.4 (Java 17), Spring Authorization Server 1.3.1, Postgres (JDBC + Flyway), Redis (revocation), OIDC, dynamic client registration, admin client API, and matching module structure.

## Run
```bash
docker compose up -d postgres redis
mvn -q -DskipTests package
java -jar authorization-server/target/authorization-server-0.0.1-SNAPSHOT.jar
java -jar resource-server/target/resource-server-0.0.1-SNAPSHOT.jar
java -jar client-app/target/client-app-0.0.1-SNAPSHOT.jar
```

- Auth Server: http://localhost:9000
- Resource Server: http://localhost:9090
- Client App: http://localhost:8082

**Steps to run:**
1. ```UI -> OAuthLoginRedirectUI -> npm i-> npm run build```
2. ```cp -R dist/* ../authorization-server/src/main/resources/static/auth/login/```
3. Start the Authorization Server (verify `http://localhost:9000/oauth2/jwks` loads).
4. Start the Resource Server.
5. Start Client (Note: This is just dummy client for awareness).
6. login with `http://localhost:8082`
7. ```UI->CustomOAuthUI->npm i->npm run dev```
NOTE: I have added a dummy credential for normal user development: `username: user`, and `password: password`, for admin role `username: admin` and `password:admin123`.

## Client registration
RFC-style:
```bash
curl -v -u admin:admin123 http://localhost:9000/admin/clients \
  -H 'Content-Type: application/json' \
  -d '{
    "clientId":"unique",
    "clientName":"unique",
    "redirectUris":["http://localhost:8082/login/oauth2/code/another-web"],
    "grantTypes":["authorization_code","refresh_token"],
    "scopes":["openid","profile","email","api.read"],
    "publicClient": false
  }'
```
**Result:**
```
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* Connected to localhost (::1) port 9000
* Server auth using Basic with user 'admin'
> POST /admin/clients HTTP/1.1
> Host: localhost:9000
> Authorization: Basic YWRtaW46YWRtaW4xMjM=
> User-Agent: curl/8.7.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 288
> 
* upload completely sent off: 288 bytes
< HTTP/1.1 200 
< Vary: Origin
< Vary: Access-Control-Request-Method
< Vary: Access-Control-Request-Headers
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 0
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Sun, 31 Aug 2025 12:50:19 GMT
< 
* Connection #0 to host localhost left intact
{"client_id":"another-web-new","client_secret":"e0bUILUxS5HhYIApKi84xkBlqEb3Vp0srTIDsPpHt0ycWKQWCV39dERjvZ6KBay5","redirect_uris":["http://localhost:8082/login/oauth2/code/another-web"],"grant_types":["authorization_code","refresh_token"],"scopes":["openid","profile","email","api.read"]}%  
```

Admin API:
```bash
curl -v -u admin:admin123 http://localhost:9000/admin/clients   -H 'Content-Type: application/json'   -d '{"clientId":"client-app","clientName":"Client App","redirectUris":["http://127.0.0.1:8082/login/oauth2/code/client-app"],"grantTypes":["authorization_code","refresh_token"],"scopes":["openid","profile","email","api.read"],"publicClient":false,"clientSecret":"client-secret"}'
```

## Revocation
```bash
curl -v -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:9000/revoke
```
Resource server enforces revoked JTI via Redis.

## List all register clients
```bash
 curl -i http://localhost:9000/admin/clients \
  -H "Origin: http://localhost:5173" \
  -H "Authorization: Basic $(printf 'admin:admin123' | base64)" \
  --cookie-jar /tmp/c.jar --cookie /tmp/c.jar
```
**Result:**
```
[{"clientId":"another-web","clientName":"Another Web","publicClient":false},{"clientId":"another-web-new","clientName":"Another Web-new","publicClient":false},{"clientId":"client-Hf8ByV1U2f2Ykj4TM_6lFfyykLzWGfd-","clientName":"My DCR App","publicClient":false},{"clientId":"client-app","clientName":"dbc18a88-98f5-424e-88ed-1de887c8a328","publicClient":false},{"clientId":"client-eshO2IJ-HSTaDhX_6gb0fYGAnCk8Zi8a","clientName":"My DCR App","publicClient":false},{"clientId":"client-hsop9qaPN35Wbsp1UAzrUC5fydWAXElN","clientName":"My DCR App","publicClient":false},{"clientId":"client-kZpqP8Vex0wxs1sb7XMZHSkK7eGVhhY5","clientName":"My DCR App","publicClient":false},{"clientId":"my-dcr-app","clientName":"My DCR App","publicClient":false},{"clientId":"my-web-app","clientName":"My Web App","publicClient":false}]%
```
## Frontend Test
```bash
curl -i http://localhost:9000/admin/clients \
  -H "Origin: http://localhost:5173" \
  -H "Authorization: Basic $(printf 'admin:admin123' | base64)" \
  --cookie-jar /tmp/c.jar --cookie /tmp/c.jar
```


