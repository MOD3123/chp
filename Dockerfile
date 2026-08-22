
### Oprav celý `Dockerfile`

V GitHub repozitári `MOD3123/chp` teda nastav `Dockerfile` presne na toto:

```dockerfile
FROM alpine:3.22

RUN apk add --no-cache \
    ca-certificates \
    curl \
    tar \
    gettext \
    python3

ARG WIREPROXY_VERSION=1.1.2

RUN curl -fL \
    "https://github.com/windtf/wireproxy/releases/download/v${WIREPROXY_VERSION}/wireproxy_linux_amd64.tar.gz" \
    -o /tmp/wireproxy.tar.gz \
    && tar -xzf /tmp/wireproxy.tar.gz -C /usr/local/bin \
    && chmod +x /usr/local/bin/wireproxy \
    && rm /tmp/wireproxy.tar.gz

WORKDIR /app

COPY server.py .
COPY wireproxy.conf .

ENV SOCKS5_PORT=1080

CMD ["sh", "-c", "envsubst < /app/wireproxy.conf > /tmp/wireproxy.conf && wireproxy -c /tmp/wireproxy.conf & exec python3 /app/server.py"]
