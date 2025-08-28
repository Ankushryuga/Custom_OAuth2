<h3 align="center"> Hi there 👋, thank you for visiting this repo</h3>

<p align="center"> This repo is just POC of OAuth2.0 server using Java Spring Boot and will be using this OAuth2.0 for all of my application</p>

<p align="center"> If you find this repo helpful, please give this repo a star </p>

**Minimum requirement to run this**
1. JVM         -- installed
2. MVN         -- installed
3. postgreSQL  -- installed

NOTE: Change the database information in `AuthorizationServer/resources/application.yml` file

**Steps to Run**

1. Start the Authorization Server (verify `http://localhost:9000/oauth2/jwks` loads).
2. Start the Resource Server.
3. Start Client
4. login with `http://localhost:8080`


NOTE: I have added a dummy credential for development: `username: user`, and `password: password`.


**Notice: Lots of improvement coming ahead**
