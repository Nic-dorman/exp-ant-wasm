#!/bin/bash
# Stop all ant nodes across all testnet droplets
# Run from local machine

WORKERS=(
    "142.93.52.129"   # ant-worker-1
    "24.199.82.114"   # ant-worker-2
    "192.34.62.192"   # ant-worker-3
    "159.223.131.196" # ant-worker-4
)

echo "=== Stopping All Testnet Nodes ==="

for i in "${!WORKERS[@]}"; do
    IP="${WORKERS[$i]}"
    WORKER_NUM=$((i + 1))
    START_INDEX=$((i * 50))

    echo "Stopping nodes on ant-worker-${WORKER_NUM} ($IP)..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "
        for j in \$(seq ${START_INDEX} $((START_INDEX + 49))); do
            systemctl stop ant-node-\${j} 2>/dev/null || true
            systemctl disable ant-node-\${j} 2>/dev/null || true
        done
        echo 'All nodes stopped on this worker'
    " &
done

# Wait for all SSH commands to complete
wait

echo ""
echo "=== All nodes stopped ==="
