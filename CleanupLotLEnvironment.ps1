# CleanupEnvironment.ps1
# This script forcefully stops and removes Docker containers, images, and volumes
# specifically created by BuildAndRunLotLEnvironment.ps1, excluding the ELK image.

Write-Host "Stopping and forcefully removing containers..."

# Step 1: Stop and remove the Malicious Server container
Write-Host "Stopping the malicious server container..."
docker stop malicious-server --time 30  # Grace period of 30 seconds to stop
docker rm malicious-server --force

# Step 2: Stop and remove the C2 Server container
Write-Host "Stopping the c2 server container..."
docker stop c2-server --time 30  # Grace period of 30 seconds to stop
docker rm c2-server --force

# Step 3: Stop and remove the ELK container using Docker Compose
Write-Host "Stopping the ELK container..."
Push-Location "./elk"
docker-compose down --volumes --remove-orphans --timeout 30  # Forcefully remove containers and associated volumes
Pop-Location

Write-Host "Containers stopped and removed."

# Step 4: Remove the Malicious Server Docker Image, excluding `sebp/elk`
Write-Host "Removing malicious server image..."
$imagesToRemove = @("malicious-url-sim","c2-server-sim")
foreach ($image in $imagesToRemove) {
    if (docker images -q $image) {
        docker rmi $image --force
    }
}

Write-Host "Malicious server image removed."

# Step 5: Remove specific volumes created during setup
Write-Host "Removing associated Docker volumes..."

# Get the list of volumes created by the ELK stack or malicious server (if any specific volumes were created).
# Here, we're assuming that no named volumes were created by the script, but if they were, specify their names:
$volumesToRemove = @("elk-esdata")  # Replace with actual volume names if any were created
foreach ($volume in $volumesToRemove) {
    if (docker volume ls -q -f name=$volume) {
        docker volume rm $volume --force
    }
}

Write-Host "Associated volumes removed."

# Step 5: Skip removal of ELK image
Write-Host "Retaining other images as per requirements."

Write-Host "Cleanup complete. All targeted containers, images (excluding other big images), and volumes have been forcefully removed."
