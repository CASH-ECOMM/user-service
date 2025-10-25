FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
  gcc \
  postgresql-client \
  && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Generate gRPC code from proto files using the script
RUN chmod +x generate_grpc.sh && ./generate_grpc.sh

# Expose gRPC port
EXPOSE 50051

# Run the application
CMD ["python", "main.py"]
