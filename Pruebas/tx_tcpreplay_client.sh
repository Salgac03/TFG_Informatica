#!/usr/bin/env bash
set -euo pipefail

IFACE="$1"
PCAP="$2"
DURATION="$3"
PPS_TARGET="$4"
RX_HOST="$5"
RX_PORT="${6:-5555}"
LABEL="${7:-run_$(date +%Y%m%d_%H%M%S)}"

if [[ -z "$IFACE" || -z "$PCAP" || -z "$DURATION" || -z "$PPS_TARGET" || -z "$RX_HOST" ]]; then
  echo "Uso: sudo $0 <interfaz> <pcap> <duracion_s> <pps_target> <rx_host> [rx_port=5555] [label]"
  exit 1
fi

if [[ ! -f "$PCAP" ]]; then
  echo "Error: PCAP no existe: $PCAP"
  exit 1
fi

echo "[TX] Ordenando captura en RX: label=${LABEL}, duration=${DURATION}s, pps_target=${PPS_TARGET}"
echo "START ${LABEL} ${DURATION} ${PPS_TARGET}" | nc "$RX_HOST" "$RX_PORT" -w 2

sleep 0.5

echo "[TX] Ejecutando tcpreplay --pps=${PPS_TARGET}"
timeout "$DURATION" tcpreplay --intf1="$IFACE" --pps="$PPS_TARGET" "$PCAP" >/dev/null 2>&1 || true

echo "[TX] Fin. CSV generado en RX: ${LABEL}.csv"
