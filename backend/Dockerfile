FROM python:3.11-slim

WORKDIR /workspace

# Install system dependencies needed for compiling standard libraries (like psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements first to leverage caching
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source directory into /workspace/backend
COPY . /workspace/backend

# Set environment paths
ENV PYTHONPATH=/workspace

EXPOSE 8000

# Health check using lightweight Python built-in urllib
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# Run FastAPI app via Uvicorn
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
