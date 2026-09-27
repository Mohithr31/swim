FROM python:3.11-slim

WORKDIR /app

# Install system utilities & C compiler
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    libc6-dev \
    tar \
    gzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV JOCKY_HOST=0.0.0.0
ENV JOCKY_PORT=5000
ENV JOCKY_DB=/app/data/jocky_forensics.db
ENV JOCKY_EVIDENCE_DIR=/app/data/evidence

VOLUME ["/app/data"]

CMD ["python", "-m", "server.server"]
