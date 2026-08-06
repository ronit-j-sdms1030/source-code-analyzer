#!/bin/bash
set -e

echo "=========================================="
echo " Starting Source Code Analyzer            "
echo "=========================================="

echo "[1/3] Setting up backend environment..."
cd backend
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Installing backend dependencies (first time only)..."
    pip install -r requirements.txt
else
    source venv/bin/activate
fi
cd ..

echo "[2/3] Building frontend..."
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies (first time only)..."
    npm install
fi
npm run build
cd ..

echo "[3/3] Starting backend server..."
cd backend
echo "The app will be accessible at http://localhost:5000"
python3 app.py
