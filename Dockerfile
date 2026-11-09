FROM mcr.microsoft.com/playwright/python:v1.41.0-jammy
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y xvfb && rm -rf /var/lib/apt/lists/*
CMD ["xvfb-run", "-a", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
