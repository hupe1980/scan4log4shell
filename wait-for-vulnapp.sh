#!/bin/sh
# wait-for-vulnapp.sh

set -e
    
until curl --header "X-Api-Version: 123" vulnapp:8080; do
  >&2 echo "Vulnapp is unavailable - sleeping"
  sleep 1
done
  
>&2 echo "Vulnapp is up - executing command"
exec "$@"