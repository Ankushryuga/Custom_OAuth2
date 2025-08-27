FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml /workspace/pom.xml
COPY /oauth2-client/pom.xml /workspace/oauth2-client/pom.xml
COPY /oauth2-client/src /workspace/oauth2-client/src
RUN --mount=type=cache,target=/root/.m2 mvn -q -f oauth2-client/pom.xml -DskipTests package
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/oauth2-client/target/*.jar /app/app.jar
EXPOSE 8082
ENTRYPOINT ["java","-jar","/app/app.jar"]
