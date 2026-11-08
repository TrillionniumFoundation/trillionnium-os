#!/system/bin/sh
set -eu
ulimit -c 0
parent_ns="$(readlink /proc/1/ns/net)"
child_ns="$(readlink /proc/self/ns/net)"
printf "HEPTA_PARENT_NET=%s\nHEPTA_CHILD_NET=%s\n" "$parent_ns" "$child_ns"
[ "$parent_ns" != "$child_ns" ] || exit 88
routes="$(ip route)"
printf "HEPTA_ROUTES=%s\n" "$routes"
[ -z "$routes" ] || exit 89
printf "HEPTA_WRAPPER_ID="; id
printf "HEPTA_WRAPPER_SELINUX="; cat /proc/self/attr/current; echo
cd /data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model
export LD_LIBRARY_PATH=/data/local/tmp/hepta-geniex-core-r2-20261108/lib:/data/local/tmp/hepta-geniex-core-r2-20261108/lib/llama_cpp:/data/local/tmp/hepta-geniex-core-r2-20261108/lib/qairt:/data/local/tmp/hepta-geniex-core-r2-20261108/lib/qairt/htp-files:/system/lib64:/vendor/lib64
export GENIEX_PLUGIN_PATH=/data/local/tmp/hepta-geniex-core-r2-20261108/lib
export GENIEX_QAIRT_LIB=/data/local/tmp/hepta-geniex-core-r2-20261108/lib/qairt/htp-files
export ADSP_LIBRARY_PATH='/data/local/tmp/hepta-geniex-core-r2-20261108/lib/qairt/htp-files;/vendor/lib/rfsa/adsp'
export GGML_HEXAGON_PROFILE=0
export GGML_HEXAGON_VERBOSE=0
mkdir -m 700 /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar
cp /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar-prompt.txt /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/prompt.txt
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/prompt.txt
cp /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar-system.txt /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/system.txt
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/system.txt
cp /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar-grammar.gbnf /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/grammar.gbnf
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/grammar.gbnf
sha256sum /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/prompt.txt /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/system.txt /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/grammar.gbnf
exec /system/bin/timeout -k 5 60 /data/local/tmp/hepta-geniex-core-r2-20261108/hepta-geniex-once-r2 --request-id 41692e43d6ec42ca86ced39125d64ac6 --mode vlm --runtime qairt --compute npu --model /data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model/genie_config.json --tokenizer /data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model/tokenizer.json --ctx-size 0 --threads 4 --max-tokens 8 --timeout-ms 55000 --log-level info --prompt-file /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/prompt.txt --system-file /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/system.txt --result-file /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/result.json --text-file /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/generated.txt --grammar-file /data/local/tmp/hepta-geniex-core-r2-20261108/02-invalid-grammar/grammar.gbnf
