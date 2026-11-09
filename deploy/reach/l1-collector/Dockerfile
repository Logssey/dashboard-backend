# syntax=docker/dockerfile:1
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache curl jq && adduser -D -u 10001 collector
COPY --chmod=0555 collect.sh inventory.jq /app/
USER 10001
ENTRYPOINT ["/app/collect.sh"]
