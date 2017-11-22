FROM openjdk:8-jre-slim

COPY app/ /app

WORKDIR /app
ENTRYPOINT ["java", "-jar", "/app/foilen-infra-bootstrap.jar"]
