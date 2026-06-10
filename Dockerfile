FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Expose default port
EXPOSE 8080

# Copy application code into container
COPY . .

# Run secure python host engine in HTTP mode (SSL is terminated at the AWS Load Balancer level)
CMD ["python", "host_secure.py", "--no-ssl", "--bind", "0.0.0.0", "--port", "8080"]
