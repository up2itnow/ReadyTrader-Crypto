FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies if needed (e.g. for building some python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN python -m pip install --upgrade pip && python -m pip install --no-cache-dir -r requirements.txt

# Expose MCP stdio (default) and FastAPI port
EXPOSE 8000

# Copy application code
COPY . .

# Ensure data directory exists
RUN mkdir -p data

# Entry point: Run the MCP server. 
# Optional Sidecar: If you want to run the FastAPI server, use 
# 'uvicorn api_server:app --host 0.0.0.0 --port 8000'
CMD ["python", "app/main.py"]
