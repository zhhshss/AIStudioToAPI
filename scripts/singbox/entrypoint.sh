#!/bin/sh
set -eu

runtime_dir="${SINGBOX_RUNTIME_DIR:-/tmp/private-runtime}"
config_path="${SINGBOX_CONFIG_PATH:-${runtime_dir}/config.json}"
mixed_port="${SINGBOX_MIXED_PORT:-2080}"
bin_dir="${runtime_dir}/bin"
singbox_pid=""
app_pid=""

random_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 4
        return
    fi
    tr -dc 'a-f0-9' </dev/urandom | head -c 8
}

generic_name() {
    prefix="$1"
    echo "${prefix}-$(random_token)" | cut -c1-15
}

cleanup() {
    if [ -n "${app_pid}" ]; then
        kill "${app_pid}" 2>/dev/null || true
        wait "${app_pid}" 2>/dev/null || true
    fi
    if [ -n "${singbox_pid}" ]; then
        kill "${singbox_pid}" 2>/dev/null || true
        wait "${singbox_pid}" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

umask 077
mkdir -p "${runtime_dir}" "${bin_dir}"

if [ -z "${PROCESS_NAME:-}" ]; then
    PROCESS_NAME="$(generic_name worker)"
    export PROCESS_NAME
fi

if [ -n "${SINGBOX_OUTBOUND_JSON:-}" ] || \
    [ -n "${SINGBOX_OUTBOUND_JSON_BASE64:-}" ] || \
    [ -n "${SINGBOX_OUTBOUND_FILE:-}" ] || \
    [ -n "${SINGBOX_SUBSCRIPTION_URL:-}" ]; then
    node "/app/scripts/singbox/build-config.js" "${config_path}"
    if [ -z "${SINGBOX_PROCESS_NAME:-}" ]; then
        SINGBOX_PROCESS_NAME="$(generic_name helper)"
    fi
    singbox_bin="${bin_dir}/${SINGBOX_PROCESS_NAME}"
    cp "/usr/local/bin/sing-box" "${singbox_bin}"
    chmod 0755 "${singbox_bin}"
    "${singbox_bin}" check -c "${config_path}"
    "${singbox_bin}" run -c "${config_path}" &
    singbox_pid="$!"

    proxy_url="http://127.0.0.1:${mixed_port}"
    export HTTP_PROXY="${proxy_url}"
    export HTTPS_PROXY="${proxy_url}"
    export http_proxy="${proxy_url}"
    export https_proxy="${proxy_url}"
    export NO_PROXY="localhost,127.0.0.1,::1,0.0.0.0${NO_PROXY:+,${NO_PROXY}}"
    export no_proxy="${NO_PROXY}"

    attempts=0
    while ! node -e "const net=require('net');const s=net.connect(${mixed_port},'127.0.0.1',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));"; do
        attempts=$((attempts + 1))
        if [ "${attempts}" -ge 50 ] || ! kill -0 "${singbox_pid}" 2>/dev/null; then
            echo "[Runtime] Local helper did not become ready." >&2
            exit 1
        fi
        sleep 0.1
    done
fi

node_bin="${bin_dir}/${PROCESS_NAME}"
ln -sf "$(command -v node)" "${node_bin}"
"${node_bin}" "/app/main.js" &
app_pid="$!"
wait "${app_pid}"
