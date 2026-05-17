FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nikto \
    nuclei \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY scanner.py .
COPY wordlists/ /wordlists/

# Create non-root user
RUN useradd -m scanner && chown -R scanner:scanner /home/scanner
USER scanner
WORKDIR /home/scanner

# Entry point
ENTRYPOINT ["python", "/scanner.py"]
