FROM python:3.11-slim

WORKDIR /app

# Install system dependencies if needed (e.g. for building some python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY verify_server.py .
COPY paper_engine.py .
COPY intelligence.py .
COPY backtest_engine.py .
COPY market_regime.py .
COPY risk_manager.py .

# Default command
CMD ["fastmcp", "run", "server.py"]
