FROM openjdk:11-jre-slim

RUN export TERM=dumb ; \
  apt-get update && apt-get install -y \
    apt-transport-https apt-utils curl ca-certificates gnupg \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Infra apps to share
RUN export TERM=dumb ; \
  echo "deb https://dl.bintray.com/foilen/debian stable main" > /etc/apt/sources.list.d/foilen.list \
  && apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 379CE192D401AB61 \
  && apt-get update && apt-get install -y \
    foilen-haproxy=1.7.12-2 services-execution=1.0.0 \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY app/ /app

WORKDIR /app
ENTRYPOINT ["java", "-jar", "/app/foilen-infra-bootstrap.jar"]
