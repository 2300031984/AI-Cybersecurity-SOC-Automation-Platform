FROM python:3.11-slim

WORKDIR /workspace

# Copy requirements first to leverage caching
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy dashboard source directory into /workspace/dashboard
COPY . /workspace/dashboard

# Set python path
ENV PYTHONPATH=/workspace

EXPOSE 8501

# Run Streamlit
CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
