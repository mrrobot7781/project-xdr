# Use a lightweight official Python runtime
FROM python:3.10-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies safely by only allowing pre-compiled binary wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary :all: -r requirements.txt || pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .

# Create a non-privileged system user and group
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Change ownership of the working directory to the non-root user
RUN chown -R appuser:appuser /app

# Switch to the non-privileged user
USER appuser

# Expose port 5000
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
