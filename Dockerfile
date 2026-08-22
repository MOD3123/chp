FROM alpine:latest

RUN apk add --no-cache \
    curl \
    socat \
    gettext \
    ca-certificates \
    tar

# Stiahni konkrétny Linux x86_64 release wireproxy.
# URL uprav podľa verzie, ktorú chceš používať.
ARG WIREPROXY_VERSION=1.0.8
RUN curl -fL \
    "https://github.com/octeep/wireproxy/releases/download/v${WIREPROXY_VERSION}/wireproxy_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin/ \
    && chmod +x /usr/local/bin/wireproxy

WORKDIR /app

COPY wireproxy.conf .

CMD ["sh", "-c", "\
    envsubst < /app/wireproxy.conf > /app/running.conf && \
    wireproxy -c /app/running.conf & \
    sleep 3 && \
    exec socat TCP-LISTEN:${PORT},fork,reuseaddr SOCKS5:127.0.0.1:127.0.0.1:${TARGET_PORT},socksport=1080 \
"]
