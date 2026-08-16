# redis-py — the client the Python half of the world uses (МR0, recon item 2).
FROM python:3.12-slim
RUN pip install --no-cache-dir "redis==5.2.1"
WORKDIR /app
COPY scenarios.py /app/
ENTRYPOINT ["python3", "/app/scenarios.py"]
