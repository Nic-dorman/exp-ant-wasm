#!/bin/bash
# Deploy ant-node to all testnet droplets
# Run from local machine with SSH access to droplets

set -e

# Droplet IPs
WORKERS=(
    "142.93.52.129"   # ant-worker-1
    "24.199.82.114"   # ant-worker-2
    "192.34.62.192"   # ant-worker-3
    "159.223.131.196" # ant-worker-4
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_URL="https://github.com/WithAutonomi/ant-node/releases/download/v0.2.0/ant-node-cli-linux-x64.tar.gz"

echo "=== Autonomi Testnet Deployment ==="
echo "Deploying to ${#WORKERS[@]} droplets"
echo ""

for i in "${!WORKERS[@]}"; do
    IP="${WORKERS[$i]}"
    WORKER_NUM=$((i + 1))

    echo "=== Deploying to ant-worker-${WORKER_NUM} ($IP) ==="

    # Copy scripts
    echo "Copying scripts..."
    scp -o StrictHostKeyChecking=no \
        "$SCRIPT_DIR/setup-limits.sh" \
        "$SCRIPT_DIR/spawn-nodes.sh" \
        "$SCRIPT_DIR/start-nodes.sh" \
        "$SCRIPT_DIR/check-health.sh" \
        "root@${IP}:/usr/local/bin/"

    # Make scripts executable
    ssh -o StrictHostKeyChecking=no "root@${IP}" "chmod +x /usr/local/bin/*.sh"

    # Download and install binary
    echo "Downloading and installing ant-node..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "
        cd /tmp
        curl -sL '${BINARY_URL}' -o ant-node.tar.gz
        tar xzf ant-node.tar.gz
        mv ant-node /usr/local/bin/
        chmod +x /usr/local/bin/ant-node
        rm -f ant-node.tar.gz
        /usr/local/bin/ant-node --version
    "

    # Configure system limits
    echo "Configuring system limits..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "/usr/local/bin/setup-limits.sh"

    # Create systemd services
    echo "Creating node services..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "/usr/local/bin/spawn-nodes.sh $((i * 50))"

    echo "Worker ${WORKER_NUM} ready!"
    echo ""
done

echo "=== Deployment Complete ==="
echo "To start all nodes, run: ./start-all.sh"
