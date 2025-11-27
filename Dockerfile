FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir flask requests

# Copy the application code
COPY waf_proxy.py .

# Environment variables to ensure output logs show up immediately
ENV PYTHONUNBUFFERED=1

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["python", "waf_proxy.py"]