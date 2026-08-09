#!/usr/bin/env sh
set -eu
cp -n .env.example .env || true
docker compose up --build

