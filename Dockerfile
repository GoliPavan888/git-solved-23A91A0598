FROM python:3.11-slim

RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app /app/app
COPY student_private.pem /app/student_private.pem
COPY encrypted_seed.txt /app/encrypted_seed.txt

COPY cron /cron
COPY scripts /scripts

RUN chmod 0644 /cron/2fa-cron && crontab /cron/2fa-cron
RUN chmod +x /scripts/log_2fa_cron.py

RUN mkdir -p /data /cron-output

CMD ["sh", "-c", "cron -f & uvicorn app.main:app --host 0.0.0.0 --port 8080"]
