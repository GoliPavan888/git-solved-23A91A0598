FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir fastapi uvicorn[standard] requests cryptography pyotp

COPY cron/2fa-cron /etc/cron.d/2fa-cron
RUN chmod 0644 /etc/cron.d/2fa-cron && crontab /etc/cron.d/2fa-cron

RUN touch /app/cron/last_code.txt

CMD service cron start && \
    uvicorn app.main:app --host 0.0.0.0 --port 8000
