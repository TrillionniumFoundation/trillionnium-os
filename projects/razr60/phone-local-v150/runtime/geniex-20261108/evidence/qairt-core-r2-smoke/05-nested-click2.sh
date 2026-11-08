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
mkdir -m 700 /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2
cp /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2-prompt.txt /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/prompt.txt
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/prompt.txt
cp /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2-system.txt /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/system.txt
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/system.txt
cp /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2-grammar.gbnf /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/grammar.gbnf
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/grammar.gbnf
cp /data/local/tmp/hepta-geniex-npu-v0100-20261108/fixture_2_2x.png /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/image.png
chmod 600 /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/image.png
sha256sum /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/prompt.txt /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/system.txt /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/grammar.gbnf /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/image.png
exec /system/bin/timeout -k 5 60 /data/local/tmp/hepta-geniex-core-r2-20261108/hepta-geniex-once-r2 --request-id 85d6aae6994c42c6b6d895febc914a85 --mode vlm --runtime qairt --compute npu --model /data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model/genie_config.json --tokenizer /data/local/tmp/hepta-qwen3vl4b-qairt-r1-20261108/model/tokenizer.json --ctx-size 0 --threads 4 --max-tokens 160 --timeout-ms 55000 --log-level info --prompt-file /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/prompt.txt --system-file /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/system.txt --result-file /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/result.json --text-file /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/generated.txt --grammar-file /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/grammar.gbnf --image /data/local/tmp/hepta-geniex-core-r2-20261108/05-nested-click2/image.png
