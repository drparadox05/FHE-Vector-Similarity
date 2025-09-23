#!/bin/bash
# Encrypted Biometric Similarity System - One-Command Demo Script
# This script builds and runs the complete demonstration

echo "========================================"
echo " Encrypted Biometric Similarity Demo"
echo "========================================"
echo

# Check if build directory exists
if [ ! -d "build" ]; then
    echo "Creating build directory..."
    mkdir build
fi

# Navigate to build directory
cd build

echo "Building project..."
cmake --build build
if [ $? -ne 0 ]; then
    echo "ERROR: Build failed!"
    exit 1
fi

echo
echo "========================================"
echo " Running Encrypted Similarity Demo"
echo "========================================"
echo

# Run the demo
./encrypted_similarity
if [ $? -ne 0 ]; then
    echo "ERROR: Demo execution failed!"
    exit 1
fi

echo
echo "========================================"
echo " Demo completed successfully!"
echo "========================================"
echo
echo "To modify configuration, edit src/main.cpp"
echo "To scale to 1000 vectors, change config.numVectors = 1000"
echo
