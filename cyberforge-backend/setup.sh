#!/bin/bash
# ================================================================
#  CyberForge Backend — Local Development Setup Script
# ================================================================
set -e

echo "🛡️  CyberForge Forensics Platform — Setup"
echo "=========================================="

# 1. Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating Python virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate

# 2. Install system dependencies (Ubuntu/Debian)
echo "🔧 Checking system dependencies..."
if command -v apt-get &> /dev/null; then
    echo "Installing system libs (requires sudo): libmagic, yara, libfuzzy..."
    sudo apt-get update -qq
    sudo apt-get install -y libmagic1 yara libyara-dev libfuzzy-dev build-essential
fi

# 3. Install Python dependencies
echo "🐍 Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# 4. Setup .env if not exists
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env from template..."
    cp .env.example .env
    echo "⚠️  Please edit .env and add your API keys (VirusTotal, AbuseIPDB, Anthropic)"
fi

# 5. Create upload directory
mkdir -p uploads

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your database URL and API keys"
echo "  2. Start PostgreSQL & Redis (or use: docker-compose up postgres redis -d)"
echo "  3. Run: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
echo "  4. Visit: http://localhost:8000/docs for interactive API documentation"
echo ""
