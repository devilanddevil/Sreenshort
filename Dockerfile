FROM python:3.9-slim

# Install system dependencies (Tesseract) using -y to avoid prompts
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the port Render expects
EXPOSE 10000

# Optimize memory usage for Render Free Tier (Critical for Tesseract)
ENV OMP_THREAD_LIMIT=1

# Run the application
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:10000"]
