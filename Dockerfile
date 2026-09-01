# ==============================================================================
# CYBER SENTINEL - PRODUCTION DOCKERFILE FOR CLOUD DEPLOYMENT
# Passive Unidirectional AI Threat Detection Platform (SIH Problem ID 26145)
# ==============================================================================

FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code and datasets
COPY . .

# Expose Web Port
EXPOSE 8000

# Run Uvicorn server with dynamic port binding for Render / Railway / Heroku
CMD ["sh", "-c", "uvicorn diode_sentinel.server.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
