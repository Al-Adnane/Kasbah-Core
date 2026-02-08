FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002

# Fail fast if syntax is broken (prevents "random 8002 down" situations)
RUN python -m py_compile apps/api/main.py

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8002"]
