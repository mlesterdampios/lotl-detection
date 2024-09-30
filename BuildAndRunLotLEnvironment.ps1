# BuildAndRunLotLEnvironment.ps1
# This script builds and runs the Docker environment for testing LotL activities.

# Navigate to script directory
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

# Step 1: Build the Malicious Server Docker Image
Write-Host "Building malicious server image..."
Push-Location "./malicious-server"
docker build -t malicious-url-sim .
Pop-Location

# Step 2: Build the C2 Server Docker Image
Write-Host "Building C2 server image..."
Push-Location "./c2-server"
docker build -t c2-server-sim .
Pop-Location

# Step 3: Start the ELK Stack using Docker Compose
Write-Host "Starting ELK stack with docker-compose..."
Push-Location "./elk"
docker-compose up -d
Pop-Location

# Step 4: Run the Malicious Server Container
Write-Host "Running malicious server container..."
docker run -d --name malicious-server -p 8080:80 malicious-url-sim

# Step 5: Run the Malicious Server Container
Write-Host "Running c2 server container..."
docker run -d --name c2-server -p 4444:4444 c2-server-sim

# Step 6: Wait for ELK Stack to Start
Write-Host "Waiting for ELK stack to initialize... (this may take a few minutes)"
Start-Sleep -Seconds 60  # Adjust the sleep time based on your system performance

# Step 7: Display Container Status
Write-Host "Displaying status of running containers:"
docker ps

Write-Host "All services are up and running."
Write-Host "Kibana is accessible at http://localhost:5601"
Write-Host "The simulated malicious server is accessible at http://localhost:8080"
