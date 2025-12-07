#!/bin/sh
set -e

# Convert Docker Swarm secrets to environment variables
export_secret() {
    secret_name=$1
    env_var_name=$2
    secret_file="/run/secrets/${secret_name}"

    if [ -f "$secret_file" ]; then
        export "$env_var_name"="$(cat "$secret_file")"
        echo "Loaded secret: $env_var_name"
    fi
}

# Export all secrets as environment variables
export_secret "cookie_key" "COOKIE_KEY"
export_secret "google_client_secret" "GOOGLE_CLIENT_SECRET"
export_secret "jwt_ec_pem" "JWT_EC_PEM"
export_secret "client_jwt_ed_pem" "CLIENT_JWT_ED_PEM"
export_secret "apple_auth_key_pem" "APPLE_AUTH_KEY_PEM"
export_secret "redis_password" "REDIS_PASSWORD"

# Build REDIS_URL using the fly-redis-proxy service
# The proxy service exposes port 16379 and is accessible via service name
if [ -n "$REDIS_PASSWORD" ]; then
    export REDIS_URL="redis://default:${REDIS_PASSWORD}@fly-redis-proxy:16379"
    echo "REDIS_URL configured for fly-redis-proxy service"
fi

echo "Starting application..."
exec /app/yral-auth-v2
