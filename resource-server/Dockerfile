FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /workspace
COPY pom.xml /workspace/pom.xml
COPY /resource-server/pom.xml /workspace/resource-server/pom.xml
COPY /resource-server/src /workspace/resource-server/src
RUN --mount=type=cache,target=/root/.m2 mvn -q -f resource-server/pom.xml -DskipTests package
FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /workspace/resource-server/target/*.jar /app/app.jar
EXPOSE 8081
ENTRYPOINT ["java","-jar","/app/app.jar"]
