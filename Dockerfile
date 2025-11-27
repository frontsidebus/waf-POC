FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask requests

# Copy all service scripts
COPY logger_service.py .
COPY input_filter.py .
COPY output_filter.py .

# Create data directory
RUN mkdir -p /app/waf_data

# Environment settings
ENV PYTHONUNBUFFERED=1

# Default command (can be overridden by docker-compose)
CMD ["python", "logger_service.py"]