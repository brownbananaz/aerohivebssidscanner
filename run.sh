#!/bin/bash

# Aerohive AP Information Extractor Runner
echo "Starting Aerohive AP Information Extractor..."

# Check if Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 is not installed"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is not installed"
    exit 1
fi

# Install requirements if they don't exist
echo "Installing dependencies..."
pip3 install -r requirements.txt

# Run the application
echo "Launching application..."
python3 aerohive_extractor.py