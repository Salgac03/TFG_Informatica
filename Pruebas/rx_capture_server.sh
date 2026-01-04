#!/usr/bin/env bash
set -euo pipefail

IFACE="$1"
OUT_DIR="$2"
PORT="${3:-5555}"

if [[ -z "$IFACE" || -z "$OUT_DIR" ]]; then
  echo "Uso: sudo $0 <interfaz> <directorio_salida> [puerto_control=5555]"
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "[RX] Escuchando en puerto ${PORT} (iface=${IFACE})"
echo "[RX] Comando esperado: START <label> <duracion_s> <pps_target>"

while true; do
  LINE="$(nc -l -p "$PORT" -q 1 || true)"
  [[ -z "$LINE" ]] && continue

  CMD="$(awk '{print $1}' <<<"$LINE")"
  LABEL="$(awk '{print $2}' <<<"$LINE")"
  DURATION="$(awk '{print $3}' <<<"$LINE")"
  PPS_TARGET="$(awk '{print $4}' <<<"$LINE")"

  if [[ "$CMD" != "START" || -z "$LABEL" || -z "$DURATION" || -z "$PPS_TARGET" ]]; then
    echo "[RX] Comando inválido: $LINE"
    continue
  fi

  PCAP="${OUT_DIR}/${LABEL}.pcap"
  CSV="${OUT_DIR}/${LABEL}.csv"

  echo "timestamp,label,duration_s,pps_target,rx_packets,pps_rx,ratio_vs_target,loss_percent" > "$CSV"

  timeout "$DURATION" tcpdump -i "$IFACE" -n -U -s 0 -w "$PCAP" >/dev/null 2>&1 || true

  RX_PKTS="$(tcpdump -n -r "$PCAP" 2>/dev/null | wc -l | tr -d ' ')"
  PPS_RX="$(echo "$RX_PKTS / $DURATION" | bc)"

  if [[ "$PPS_TARGET" -gt 0 ]]; then
    RATIO="$(echo "scale=4; $PPS_RX / $PPS_TARGET" | bc)"
  else
    RATIO="0"
  fi

  EXPECTED_PKTS="$(echo "$PPS_TARGET * $DURATION" | bc)"
  if [[ "$EXPECTED_PKTS" -gt 0 ]]; then
    LOSS="$(echo "scale=4; (1 - ($RX_PKTS / $EXPECTED_PKTS)) * 100" | bc)"
  else
    LOSS="0"
  fi

  TS="$(date +"%Y-%m-%d %H:%M:%S")"
  echo "${TS},${LABEL},${DURATION},${PPS_TARGET},${RX_PKTS},${PPS_RX},${RATIO},${LOSS}" >> "$CSV"

  echo "[RX] Guardado: $CSV"
done
