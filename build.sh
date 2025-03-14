#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting build process for Cloudflare Pages...${NC}"

# Create output directory
if [ ! -d "public" ]; then
    echo -e "${YELLOW}Creating public directory...${NC}"
    mkdir -p public
fi

# Create a Python virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate the virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Copy static HTML file to public directory
echo -e "${YELLOW}Copying static files to public directory...${NC}"
cp dev.html public/index.html

# If you have any CSS or JS files, copy them too
if [ -d "static" ]; then
    cp -r static public/
fi

# Generate any additional static files if needed
# If you need to run a script to generate files, do it here
# python generate_static_files.py

echo -e "${GREEN}Build complete! Files are ready in the public directory.${NC}"
echo -e "${YELLOW}Cloudflare Pages will serve the contents of the public directory.${NC}"

# Exit successfully
exit 0