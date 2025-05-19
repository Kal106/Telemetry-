#!/bin/bash

# Set up a Python virtual environment
echo "[*] Creating virtual environment..."
python3 -m venv .venv

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Create required files
echo "[*] Creating project files..."



# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Organize files into a submission folder
# echo "[*] Organizing submission files..."
# mkdir -p submission
# mv doctor.py patient.py init.py auth.py communication.py performance.py README.md requirements.txt submission/

# # Create a ZIP archive for submission
# echo "[*] Creating ZIP archive..."
# zip -r group_lab2.zip submission/

# Deactivate virtual environment
# deactivate

echo "[✓] Setup complete! Your environment is ready."
