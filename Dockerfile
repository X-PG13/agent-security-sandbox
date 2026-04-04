FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml LICENSE README.md ./
COPY src/ src/
COPY config/ config/
COPY data/ data/

# Install the package
RUN pip install --no-cache-dir ".[all]"

# Create non-root user for security
RUN useradd -m -s /bin/bash appuser
USER appuser

# Default command
CMD ["asb", "--help"]
