# Build stage
FROM gcc:13 AS build
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make chat_server

# Runtime stage: no compiler. The entrypoint starts as root only to fix data-dir ownership,
# then drops to the unprivileged "chat" user before the server runs.
FROM debian:bookworm-slim
RUN useradd --system --no-create-home --uid 10001 chat && mkdir -p /app/data /app/public && chown chat /app/data
WORKDIR /app
COPY --from=build /src/chat_server /app/chat_server
COPY public /app/public
COPY deploy/entrypoint.sh /app/entrypoint.sh
EXPOSE 8080
# --secure marks cookies Secure and adds HSTS (TLS is terminated by the platform / proxy in front),
# --trust-proxy reads the client IP from X-Forwarded-For. Both are set in entrypoint.sh.
ENTRYPOINT ["/app/entrypoint.sh"]
