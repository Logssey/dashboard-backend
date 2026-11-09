# syntax=docker/dockerfile:1
# Digests resolve the official multi-platform Temurin 21 images. Update together
# after a reviewed Java security update; publish the resulting application image by digest.
FROM eclipse-temurin:21-jdk-jammy@sha256:4b1a74fbffbe6b4e7b6f0171a472478282fb463790a51edf10e465d578f22b69 AS build
WORKDIR /workspace
COPY gradle/ gradle/
COPY gradlew build.gradle settings.gradle ./
COPY src/ src/
COPY secret-worker/build.gradle secret-worker/build.gradle
COPY secret-worker/src/ secret-worker/src/
COPY iac-worker/build.gradle iac-worker/build.gradle
COPY iac-worker/src/ iac-worker/src/
COPY reach-analyzer/build.gradle reach-analyzer/build.gradle
RUN chmod 755 gradlew && ./gradlew --no-daemon :bootJar :secret-worker:bootJar

FROM eclipse-temurin:21-jdk-jammy@sha256:4b1a74fbffbe6b4e7b6f0171a472478282fb463790a51edf10e465d578f22b69 AS detector
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/install-gitleaks.sh /install-gitleaks.sh
RUN sh /install-gitleaks.sh "$TARGETARCH" /out

FROM eclipse-temurin:21-jre-jammy@sha256:1eac8b8fee11ca7d6725a48bc5d41992ed1561504ebae25490d2d062847e8269 AS runtime
RUN groupadd --gid 10001 logssey && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin logssey
WORKDIR /app
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError -XX:-HeapDumpOnOutOfMemoryError -XX:-CreateCoredumpOnCrash -Djava.io.tmpdir=/tmp"
USER 10001:10001

FROM runtime AS api
COPY --from=build --chown=10001:10001 /workspace/build/libs/dashboard-backend-*.jar /app/api.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/api.jar", "--spring.config.import=file:/run/config/application.properties,configtree:/run/secrets/"]

FROM runtime AS worker
COPY --from=build --chown=10001:10001 /workspace/secret-worker/build/libs/secret-worker-*.jar /app/worker.jar
COPY --from=detector --chmod=0555 /out/gitleaks /usr/local/bin/gitleaks
COPY --from=detector /out/LICENSE /usr/share/doc/gitleaks/LICENSE
ENTRYPOINT ["java", "-jar", "/app/worker.jar", "--spring.config.import=file:/run/config/application.properties,configtree:/run/secrets/"]
