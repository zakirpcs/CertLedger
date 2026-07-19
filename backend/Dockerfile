FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root user, own the app dir and the data dir before declaring volume
RUN useradd -u 1001 -r certledger && \
    mkdir -p /ca-data && \
    chown -R certledger:certledger /app /ca-data

# Declare volume AFTER chown so Docker initialises it with certledger ownership
VOLUME ["/ca-data"]

EXPOSE 8000

USER certledger

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
