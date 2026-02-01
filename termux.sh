#!/bin/bash
# RIZER API ULTIMATE - Termux Launcher

echo "🚀 RIZER API v10.3 ULTIMATE"
echo "📱 Termux Mode"
echo ""

# Install dependencies
echo "📦 Installing dependencies..."
pip install -q flask requests pycryptodome urllib3 gunicorn 2>/dev/null

# Get IP
IP=$(ifconfig 2>/dev/null | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1' | head -n 1)
[ -z "$IP" ] && IP="localhost"

echo ""
echo "🌐 Server URLs:"
echo "   Local:  http://localhost:5000"
echo "   Network: http://$IP:5000"
echo ""
echo "📡 API Endpoint:"
echo "   /gen?rizername=Test&password=Pass&count=10&region=BD"
echo ""
echo "📥 Download:"
echo "   /download/accounts?region=BD"
echo ""
echo "⚡ Press Ctrl+C to stop"
echo ""

python app.py
