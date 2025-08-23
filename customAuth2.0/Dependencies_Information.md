**Flyway**
    - Flyway is an open-source tool used to manage database schema migrations. 
      It helps automate versioning, tracking, and applying changes to your database schema in a controlled and consistent way — similar to Git, but for your database.

**Purpose of the flyway-core package**
The flyway-core artifact is the core Flyway library that enables Java applications (especially Spring Boot apps) to use Flyway to:
Run SQL scripts to set up or update the database schema
- Automatically apply pending migrations at application startup
- Track the state and history of migrations
- Rollback or repair failed migrations

**How Flyway Works in Practice**
1. You create migration files in a resources/db/migration directory:
```
src/main/resources/db/migration/
├── V1__init_schema.sql
├── V2__add_users_table.sql
└── V3__add_index_to_users.sql
```
2. Flyway looks for files named like
    - V1__description.sql
    - V2__description.sql
    - etc.

3. When the app starts, Flyway:
    - Connects to the database
    - Checks which migrations have already been applied
    - Applies any new scripts in order

**Integration with Spring Boot**
```
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-core</artifactId>
</dependency>
```