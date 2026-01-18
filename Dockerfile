FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt requirements-web.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt -r requirements-web.txt

# Copy application
COPY . .

# Expose port
EXPOSE 5000

# Run web application
CMD ["python", "web_launcher.py"]

