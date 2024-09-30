# Use a small base image with network tools
FROM alpine:latest

# Update the package repository and install netcat
RUN apk update && apk add --no-cache netcat-openbsd

# Expose port 4444 to the host
EXPOSE 4444

# Keep the container running indefinitely without doing anything
CMD ["tail", "-f", "/dev/null"]
