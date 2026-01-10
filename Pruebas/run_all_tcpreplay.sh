#!/usr/bin/env bash
set -euo pipefail

# Ajusta si tu repo no es un git repo o si lo ejecutas desde fuera:
if git rev-parse --show-toplevel >/dev/null 2>&1; then
  REPO_ROOT="$(git rev-parse --show-toplevel)"
else
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi

MN_SCRIPT="${REPO_ROOT}/Mininet/redarbolrw1.py"
SCRIPTS_DIR="${REPO_ROOT}/Pruebas/nuevas_pruebas"

PCAP_REL="${1:-Pruebas/resultados_prueba.pcap}"
DURATION="${2:-10}"
PORT="${3:-5555}"
PREFIX="${4:-tcpreplay}"
REPS="${5:-1}"

PCAP="${PCAP_REL}"
[[ "$PCAP" != /* ]] && PCAP="${REPO_ROOT}/${PCAP}"

if [[ ! -f "$PCAP" ]]; then
  echo "ERROR: PCAP no existe: $PCAP"
  exit 1
fi

# Limpieza al salir
cleanup() {
  echo "[CLEANUP] Parando procesos..."
  [[ -n "${RX_PID:-}" ]] && kill "${RX_PID}" 2>/dev/null || true
  [[ -n "${RUN_PID:-}" ]] && kill "${RUN_PID}" 2>/dev/null || true
  [[ -n "${MN_PID:-}" ]] && kill "${MN_PID}" 2>/dev/null || true
}
trap cleanup EXIT

echo "[INFO] REPO_ROOT=${REPO_ROOT}"
echo "[INFO] PCAP=${PCAP}"

# 1) Arranca Mininet headless
echo "[INFO] Arrancando Mininet (headless)..."
sudo MN_HEADLESS=1 python3 "${MN_SCRIPT}" > /tmp/mininet_run.log 2>&1 &
MN_PID=$!

# 2) Espera a que la red esté lista (ping básico)
echo "[INFO] Esperando a que Mininet esté listo..."
sleep 2

# 3) Crea PIDs ancla (sleep) y recógelos
#    (Aquí SÍ usamos mininet CLI en modo batch: "mn -c" no, porque tú estás con script python.
#     Truco: ejecutamos comandos vía 'python -c' no sirve; así que usamos una forma robusta:
#     llamamos a 'pgrep' sobre los hosts no es fiable.
#     Solución práctica: lanzamos receptor/runner SIN mnexec, usando "mininet host cmd" no disponible.
#     Por tanto, aquí asumimos ejecución dentro del CLI NO; usaremos mnexec con PIDs ancla creados por `mnexec` entrando al netns de OVS no.
# )
echo
echo "ERROR: Para automatizar 100% con tu script Mininet, necesitamos que el script exponga PIDs o que se use una topología lanzada con 'mn' (no con script python interactivo)."
echo
echo "Solución inmediata (sin perder hoy): usa este mismo script pero en modo 'semi-automático':"
echo "  1) Deja este script corriendo para mantener Mininet vivo."
echo "  2) Abre otra terminal, entra al mininet CLI (o cambia tu script para imprimir PIDs)."
echo
exit 1
