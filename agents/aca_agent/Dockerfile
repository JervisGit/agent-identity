FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000

# Use uvicorn for proper async handling of ACA health probes
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
