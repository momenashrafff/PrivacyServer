# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt /app/

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    tesseract-ocr \
    libtesseract-dev \
    libffi-dev \
    libblas-dev \
    liblapack-dev \
    gfortran \
    pkg-config \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies in stages
RUN pip install --upgrade pip wheel setuptools
# Install numpy first as it's a key dependency
RUN pip install numpy~=1.24.0
# Install other scientific packages
RUN pip install scipy~=1.10.1 pandas~=2.0.3
# Install spacy separately
RUN pip install spacy~=3.7.2

RUN python -m spacy download en_core_web_sm
# Install remaining requirements
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . /app

# Make port 4444 available to the world outside this container
EXPOSE 4444

# Define environment variable to set the path to Tesseract executable
ENV TESSERACT_CMD=/usr/bin/tesseract

# Run app.py when the container launches
CMD ["python", "app.py"]
