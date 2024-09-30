# Use Python slim base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Create a fake "malicious" file to be served
RUN echo "This is a simulated malicious file." > fake-malware.txt

# Expose port 80 for HTTP traffic
EXPOSE 80

# Run a simple HTTP server
CMD ["python3", "-m", "http.server", "80"]
