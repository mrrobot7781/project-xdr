# Use a lightweight official Python runtime
FROM python:3.10-slim

# Create a non-root user and group for security
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Expose port 5000
EXPOSE 5000

# Run using Gunicorn (or simple app.py entrypoint)
CMD ["python", "app.py"]
