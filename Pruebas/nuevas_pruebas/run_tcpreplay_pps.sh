#!/usr/bin/env bash
set -e

# ---- PARÁMETROS ----
IFACE="$1"        # interfaz de hsrc (ej. hsrc-eth0)
PCAP="$2"         # pcap a reproducir
DURATION="$3"     # duración de cada prueba (segundos)
RX_IP="$4"        # IP del receptor (hdst)
RX_PORT="${5:-5555}"
PREFIX="${6:-tcpr}"
REPS="${7:-1}"

if [[ -z "$IFACE" || -z "$PCAP" || -z "$DURATION" || -z "$RX_IP" ]]; then
  echo "Uso:"
  echo "  $0 <iface> <pcap> <duracion_s> <rx_ip> [rx_port] [prefix] [reps]"
  exit 1
fi

# Lista de PPS a probar (ajústala si quieres)
PPS_LIST=(20000 50000 100000 150000)

for pps in "${PPS_LIST[@]}"; do
  for r in $(seq 1 "$REPS"); do
    LABEL="${PREFIX}_pps${pps}_r${r}"
    echo "[RUN] ${LABEL}"

    echo "START ${LABEL} ${DURATION} ${pps}" | nc "$RX_IP" "$RX_PORT"
    sleep 0.5

    timeout "$DURATION" tcpreplay \
      --intf1="$IFACE" \
      --pps="$pps" \
      "$PCAP" > /dev/null 2>&1 || true

    sleep 1
  done
done

echo "[DONE] Barrido de PPS terminado."
