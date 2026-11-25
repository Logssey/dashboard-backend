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
COPY compliance-worker/build.gradle compliance-worker/build.gradle
COPY compliance-worker/src/ compliance-worker/src/
RUN --mount=type=cache,target=/root/.gradle \
    chmod 755 gradlew && ./gradlew --no-daemon :bootJar :secret-worker:bootJar :compliance-worker:bootJar
# IaC worker (IaC security ADR-13). Separate step so the line above stays as the other images expect.
RUN --mount=type=cache,target=/root/.gradle \
    ./gradlew --no-daemon :iac-worker:bootJar

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
# The commit this image was built from (Dashboard deploy passes the merge commit). Reach runners ask it (GET /api/v1/reach/ci/code)
ARG LOGSSEY_BUILD_COMMIT=
ENV LOGSSEY_BUILD_COMMIT=$LOGSSEY_BUILD_COMMIT
COPY --from=build --chown=10001:10001 /workspace/build/libs/dashboard-backend-*.jar /app/api.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/api.jar", "--spring.config.import=file:/run/config/application.properties,configtree:/run/secrets/"]

FROM runtime AS worker
COPY --from=build --chown=10001:10001 /workspace/secret-worker/build/libs/secret-worker-*.jar /app/worker.jar
COPY --from=detector --chmod=0555 /out/gitleaks /usr/local/bin/gitleaks
COPY --from=detector /out/LICENSE /usr/share/doc/gitleaks/LICENSE
ENTRYPOINT ["java", "-jar", "/app/worker.jar", "--spring.config.import=file:/run/config/application.properties,configtree:/run/secrets/"]

# IaC worker: graph enrichment, path analysis, State and drift checks (IaC security ADR-13). No web port.
# AWS credentials come from a short-lived session file through AWS_CONFIG_FILE credential_process (host compose).
FROM runtime AS iac-worker
COPY --from=build --chown=10001:10001 /workspace/iac-worker/build/libs/iac-worker-*.jar /app/iac-worker.jar
ENTRYPOINT ["java", "-jar", "/app/iac-worker.jar", "--spring.config.import=file:/run/config/application.properties,configtree:/run/secrets/"]

# Prowler is pinned to the same immutable 5.46.0 release used by the API scope catalog.
# The API image never receives this executable or a Docker socket.
FROM prowlercloud/prowler:5.46.0@sha256:33b8bac58779a0ed292f6c1f40f685796e681a0a2dcc26984637f71f2b052e8e AS compliance-worker
COPY --from=runtime /opt/java/openjdk /opt/java/openjdk
COPY --from=build --chown=prowler:prowler /workspace/compliance-worker/build/libs/compliance-worker-*.jar /opt/logssey/compliance-worker.jar
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:/home/prowler/.venv/bin:${PATH}"
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError -XX:-HeapDumpOnOutOfMemoryError -XX:-CreateCoredumpOnCrash -Djava.io.tmpdir=/tmp"
USER prowler
ENTRYPOINT ["java", "-jar", "/opt/logssey/compliance-worker.jar", "--spring.config.import=file:/run/config/application.properties,configtree:/run/secrets/"]
