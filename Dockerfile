# AegisMed Healthcare DevSecOps Dockerfile
# Optimized for AWS Learner Lab, EC2, App Runner, and Local Dev

FROM python:3.11-slim

# Prevent Python from writing .pyc and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (build-essential needed for some C-extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and datasets
COPY backend/ ./backend/
COPY static/ ./static/
COPY datasets/ ./datasets/
COPY run_app.py .

# Expose FastAPI default port
EXPOSE 8000

# Health check to ensure zero-downtime container monitoring
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/datasets/info || exit 1

# Launch FastAPI server with Uvicorn
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
