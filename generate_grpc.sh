#!/bin/bash

# Script to generate gRPC Python code from proto files

echo "Generating gRPC code from proto files..."

# Determine Python binary (prefer project virtualenv if available)
if [ -d "venv" ] && [ -x "venv/bin/python" ]; then
    PYTHON_BIN="venv/bin/python"
else
    PYTHON_BIN=$(command -v python3 || command -v python)
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "Error: Python interpreter not found" >&2
    exit 1
fi

# Create the generated directory if it doesn't exist
mkdir -p app/generated

# Generate Python code from proto files
"$PYTHON_BIN" -m grpc_tools.protoc \
    -I./proto \
    --python_out=./app/generated \
    --grpc_python_out=./app/generated \
    --pyi_out=./app/generated \
    ./proto/user_service.proto

# Fix imports to use package-relative form for generated gRPC stubs
if [ -f app/generated/user_service_pb2_grpc.py ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' 's/^import user_service_pb2/from . import user_service_pb2/' app/generated/user_service_pb2_grpc.py
    else
        sed -i 's/^import user_service_pb2/from . import user_service_pb2/' app/generated/user_service_pb2_grpc.py
    fi
fi

# Create __init__.py if it doesn't exist
touch app/generated/__init__.py

echo "gRPC code generation completed successfully!"
