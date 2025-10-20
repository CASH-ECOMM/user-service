#!/bin/bash

# Setup script for the User Service

set -e

echo "=== User Service Setup ==="

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Copy environment file
if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env
    echo "Please update .env file with your configuration!"
else
    echo ".env file already exists"
fi

# Generate gRPC code
echo "Generating gRPC code..."
chmod +x generate_grpc.sh
./generate_grpc.sh

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Update .env file with your database and email configuration"
echo "2. Activate virtual environment: source venv/bin/activate"
echo "3. Run the service: python app/main.py"
echo ""
