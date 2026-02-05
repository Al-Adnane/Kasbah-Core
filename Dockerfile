FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8002

# --- CRITICAL FIX: Run the NEW main.py ---
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
