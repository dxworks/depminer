FROM eclipse-temurin:21-jre-alpine

RUN apk upgrade --no-cache

WORKDIR /app

COPY target/depminer.jar depminer.jar
COPY depminer.yml depminer.yml
COPY sanitize.yml sanitize.yml
COPY .ignore.yml .ignore.yml

RUN mkdir -p results

ENTRYPOINT ["java", "-jar", "depminer.jar"]
