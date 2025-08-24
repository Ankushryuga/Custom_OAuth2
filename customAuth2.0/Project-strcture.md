```
customAuth2.0/
├── README.md
├── pom.xml                                    # Parent POM for multi-module project
│
├── AuthorizationServer/                       # OAuth2 Authorization Server (Port: 9000)
│   ├── .gitattributes
│   ├── .gitignore
│   ├── .mvn/
│   │   └── wrapper/
│   │       └── maven-wrapper.properties
│   ├── mvnw                                   # Maven wrapper (Linux/Mac)
│   ├── mvnw.cmd                              # Maven wrapper (Windows)
│   ├── pom.xml                               # Authorization Server dependencies
│   └── src/
│       ├── main/
│       │   ├── java/com/AuthroizationServer/AuthorizationServer/
│       │   │   ├── AuthorizationServerApplication.java    # Main application class
│       │   │   ├── config/
│       │   │   │   ├── AuthorizationServerConfig.java     # OAuth2 server configuration
│       │   │   │   ├── ClientConfig.java                  # OAuth2 client registration
│       │   │   │   ├── JwkConfig.java                     # JWT key configuration
│       │   │   │   ├── PasswordConfig.java                # Password encoder
│       │   │   │   └── SecurityConfig.java                # Security configuration
│       │   │   ├── controller/
│       │   │   │   └── HomeController.java                # Home page controller
│       │   │   ├── model/
│       │   │   │   ├── Client.java                        # OAuth2 client entity
│       │   │   │   ├── Role.java                          # User role entity
│       │   │   │   └── User.java                          # User entity
│       │   │   ├── repository/
│       │   │   │   ├── ClientRepository.java              # Client data access
│       │   │   │   ├── RoleRepository.java                # Role data access
│       │   │   │   └── UserRepository.java                # User data access
│       │   │   └── service/
│       │   │       └── CustomUserDetailsService.java      # User authentication service
│       │   └── resources/
│       │       ├── application.yml                        # Configuration properties
│       │       ├── schema.sql                            # Database schema
│       │       └── db/migration/                         # Flyway migrations
│       │           ├── V1__init_oauth_client.sql         # OAuth2 tables
│       │           ├── V2__create_users_and_roles.sql    # User/Role tables
│       │           └── V3__create_clients.sql            # Client configuration
│       └── test/
│           └── java/com/AuthroizationServer/AuthorizationServer/
│               └── AuthorizationServerApplicationTests.java
│
├── ResourceServer/                            # OAuth2 Resource Server (Port: 8082)
│   ├── .gitattributes
│   ├── .gitignore
│   ├── .mvn/
│   │   └── wrapper/
│   │       └── maven-wrapper.properties
│   ├── mvnw
│   ├── mvnw.cmd
│   ├── pom.xml                               # Resource server dependencies
│   └── src/
│       ├── main/
│       │   ├── java/com/customoauth2/customAuth20/
│       │   │   ├── ResourceServerApplication.java        # Main application class
│       │   │   ├── config/
│       │   │   │   └── ResourceServerConfig.java         # JWT validation config
│       │   │   └── controller/
│       │   │       └── ResourceController.java           # Protected API endpoints
│       │   └── resources/
│       │       └── application.yml                       # JWT issuer configuration
│       └── test/
│           └── java/com/customoauth2/customAuth20/
│               └── ResourceServerApplicationTests.java
│
├── OAuth2Client/                              # Simple OAuth2 Client (Port: 8091)
│   ├── .gitattributes
│   ├── .gitignore
│   ├── .mvn/
│   │   └── wrapper/
│   │       └── maven-wrapper.properties
│   ├── mvnw
│   ├── mvnw.cmd
│   ├── pom.xml                               # OAuth2 client dependencies
│   └── src/
│       ├── main/
│       │   ├── java/com/customoauth2/customAuth20/
│       │   │   ├── Oath2ClientApplication.java           # Main application class
│       │   │   ├── config/
│       │   │   │   ├── OAuth2ClientConfig.java           # OAuth2 client configuration
│       │   │   │   └── SecurityConfig.java               # Security setup
│       │   │   └── controller/
│       │   │       └── UserController.java               # User info endpoint
│       │   └── resources/
│       │       └── application.yml                       # OAuth2 client settings
│       └── test/
│           └── java/com/customoauth2/customAuth20/
│               └── Oath2ClientApplicationTests.java
│
└── Test OAuth2 App/                          # Advanced OAuth2 Client with React Integration
    └── oauth2-client Backend/                # Backend API Server (Port: 3001)
        ├── pom.xml                           # Full-featured OAuth2 client dependencies
        └── src/
            ├── main/
            │   ├── java/com/customoauth2/customAuth20/
            │   │   ├── Oath2ClientApplication.java       # Main application class
            │   │   ├── config/
            │   │   │   └── SecurityConfig.java           # CORS + OAuth2 configuration
            │   │   └── controller/
            │   │       ├── AuthController.java           # Authentication endpoints
            │   │       ├── ProtectedController.java      # Protected API endpoints
            │   │       └── ResourceServerController.java # Resource server proxy
            │   └── resources/
            │       └── application.yml                   # OAuth2 + CORS configuration
            └── test/
                └── java/com/customoauth2/customAuth20/
                    └── Oath2ClientApplicationTests.java

```