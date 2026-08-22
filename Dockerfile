FROM alpine:latest

# Inštalácia sieťových nástrojov a stiahnutie wireproxy (obsahuje wireguard-go)
RUN apk add --no-cache curl socat gettext

# Stiahneme predkompilovaný wireproxy pre Linux x64
RUN curl -L https://github.com | tar -xz -C /usr/local/bin/

WORKDIR /app
COPY wireproxy.conf .

# Spúšťací skript: dosadí tajný kľúč, naštartuje WireGuard v userspace a vystaví web
CMD envsubst < wireproxy.conf > running.conf && \
    wireproxy -c running.conf & \
    sleep 3 && \
    # Socat prevezme váš prichádzajúci HTTPS dopyt z domu a pošle ho cez WireGuard SOCKS5 do CH
    # ZAMEŇTE "tvoja-cielova-url-vo-svajciarsku.ch" za reálny cieľ
    socat TCP-LISTEN:${PORT},fork SOCKS4A:127.0.0.1:tvoja-cielova-url-vo-svajciarsku.ch:443,socksport=1080
