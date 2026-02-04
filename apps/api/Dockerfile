FROM python:3.9-slim

# Install system dependencies needed for numpy/cryptography
RUN apt-get update && apt-get install -y --no-install-recommends gcc

WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 8002

# Default command
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8002"]
