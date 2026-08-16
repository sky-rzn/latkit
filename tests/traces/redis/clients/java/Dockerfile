# Lettuce — the Java client behind Spring Data Redis (МR0, recon item 2).
FROM maven:3-eclipse-temurin-21
WORKDIR /app
COPY pom.xml /app/
RUN mvn -q -B dependency:go-offline
COPY src /app/src
RUN mvn -q -B compile dependency:build-classpath -Dmdep.outputFile=/app/cp.txt
ENTRYPOINT ["sh", "-c", "exec java -cp /app/target/classes:$(cat /app/cp.txt) Main \"$@\"", "--"]
