#!/bin/sh
set -e

# Load Fly token from Docker secret
if [ -f /run/secrets/fly_token ]; then
    export FLY_API_TOKEN=$(cat /run/secrets/fly_token)
    echo "Loaded FLY_API_TOKEN from secret"
else
    echo "Error: fly_token secret not found"
    exit 1
fi

echo "Starting Fly Agent..."
flyctl agent run > /tmp/flyctl-agent.log 2>&1 &
AGENT_PID=$!
sleep 3

if ! kill -0 $AGENT_PID > /dev/null 2>&1; then
    echo "Error: flyctl agent failed to start"
    cat /tmp/flyctl-agent.log
    exit 1
fi
echo "Fly Agent started (PID: $AGENT_PID)"

echo "Starting Fly Redis proxy..."
/app/fly_redis_proxy.exp 2>&1 &
PROXY_PID=$!

# Wait for proxy port
echo "Waiting for Redis proxy on 0.0.0.0:16379..."
MAX_WAIT=60
WAIT_COUNT=0
while ! nc -z 127.0.0.1 16379 > /dev/null 2>&1; do
    if ! kill -0 $PROXY_PID > /dev/null 2>&1; then
        echo "Error: Fly proxy died"
        exit 1
    fi
    WAIT_COUNT=$((WAIT_COUNT + 1))
    if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
        echo "Error: Timeout waiting for Redis proxy"
        exit 1
    fi
    sleep 1
done
echo "Redis proxy is active on port 16379"

# Keep container running and forward signals
trap "echo 'Shutting down...'; kill $AGENT_PID $PROXY_PID 2>/dev/null; exit 0" SIGTERM SIGINT

# Wait for proxy process
wait $PROXY_PID
