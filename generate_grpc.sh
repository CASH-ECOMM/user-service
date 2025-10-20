#!/bin/bash

# Script to generate gRPC Python code from proto files

echo "Generating gRPC code from proto files..."

# Create the generated directory if it doesn't exist
mkdir -p app/generated

# Generate Python code from proto files
python -m grpc_tools.protoc \
    -I./proto \
    --python_out=./app/generated \
    --grpc_python_out=./app/generated \
    --pyi_out=./app/generated \
    ./proto/user_service.proto

# Create __init__.py if it doesn't exist
touch app/generated/__init__.py

echo "gRPC code generation completed successfully!"
