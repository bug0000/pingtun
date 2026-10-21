#!/bin/sh
# Install as /etc/letsencrypt/renewal-hooks/deploy/pingtun-reload-nginx.sh.
set -eu
systemctl reload nginx
