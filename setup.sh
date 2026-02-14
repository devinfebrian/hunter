#!/bin/bash
# Hunter Setup Script for Unix/Linux/macOS

set -e

echo -e "\033[36mSetting up Hunter virtual environment...\033[0m"

# Check if venv exists
if [ ! -d ".venv" ]; then
    echo -e "\033[33mCreating virtual environment...\033[0m"
    python3 -m venv .venv
fi

# Activate virtual environment
echo -e "\033[33mActivating virtual environment...\033[0m"
source .venv/bin/activate

# Upgrade pip
echo -e "\033[33mUpgrading pip...\033[0m"
python -m pip install --upgrade pip

# Install dependencies
echo -e "\033[33mInstalling dependencies...\033[0m"
pip install -r requirements.txt

# Create output directory
mkdir -p output

echo ""
echo -e "\033[32mSetup complete!\033[0m"
echo ""
echo -e "\033[36mTo activate the virtual environment, run:\033[0m"
echo -e "    source .venv/bin/activate"
echo ""
echo -e "\033[36mTo run Hunter:\033[0m"
echo -e "    python -m hunter --help"
