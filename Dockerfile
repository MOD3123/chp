FROM python:3.12-alpine

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY server.py .

ENV PYTHONUNBUFFERED=1
ENV PORT=10000

CMD ["python3", "/app/server.py"]
