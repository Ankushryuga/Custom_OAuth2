FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml /workspace/pom.xml
COPY /authorization-server/pom.xml /workspace/authorization-server/pom.xml
COPY /authorization-server/src /workspace/authorization-server/src
RUN --mount=type=cache,target=/root/.m2 mvn -q -f authorization-server/pom.xml -DskipTests package
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/authorization-server/target/*.jar /app/app.jar
EXPOSE 9000
ENTRYPOINT ["java","-jar","/app/app.jar"]
