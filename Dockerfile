FROM python:3.12-alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app

RUN pip install --no-cache-dir aiohttp aiohttp-socks

COPY server.py .

ENV PYTHONUNBUFFERED=1
ENV PORT=10000

CMD ["python3", "/app/server.py"]
