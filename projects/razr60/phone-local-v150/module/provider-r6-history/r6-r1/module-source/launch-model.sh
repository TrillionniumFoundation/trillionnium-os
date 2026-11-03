#!/system/bin/sh
# Frozen argv only; never submits a task or automatically replays work.
set -eu
umask 077
exec '/data/adb/magisk/busybox' 'env' '-i' 'PATH=/system/bin:/vendor/bin' 'TMPDIR=/data/local/tmp/hepta-phone-local-v150-r1' '/data/local/tmp/hepta-phone-local-v150-r1/bin/llama-server' '-m' '/data/local/tmp/hepta-phone-local-v150-r1/models/GUI-Owl-1.5-2B-Instruct.Q4_K_M.gguf' '--mmproj' '/data/local/tmp/hepta-phone-local-v150-r1/models/GUI-Owl-1.5-2B-Instruct.mmproj-Q8_0.gguf' '--host' '127.0.0.1' '--port' '18087' '-c' '4096' '-np' '1' '-t' '4' '-b' '256' '-ub' '128' '-ngl' '0' '--no-mmproj-offload' '--image-min-tokens' '1024' '--image-max-tokens' '1024' '--no-webui' '--jinja' '--api-key-file' '/data/local/tmp/hepta-phone-local-v150-r1/state/api.key' '--slots' '--metrics' '--no-warmup' '--alias' 'gui-owl-1.5-2b-phone-q4km'
