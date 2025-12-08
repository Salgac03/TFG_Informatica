#!/bin/bash

# --- CONFIGURACIÓN ---
OUTPUT_NAME="resultados_prueba"
PCAP_FILE="${OUTPUT_NAME}.pcap"
CSV_FILE="${OUTPUT_NAME}.csv"

# Parámetros del script de envío para el análisis
DURATION_PER_RUN=$1  # Duración de cada ejecución del python3 script (e.g., 5, 10, etc.)
INTERFACE=$2         # Interfaz de red de la prueba (e.g., hsrc-eth0)

# Array con los mismos valores de tasa de tu script de envío
TAMANYOS_DE_PRUEBA=(64 128 256 512 1024 2048)
NUM_REPETICIONES=10

# --- Verificación y Pre-ejecución ---

if [ -z "$DURATION_PER_RUN" ] || [ -z "$INTERFACE" ]; then
    echo "Uso: $0 <duracion_por_ejecucion> <interfaz>" >&2
    echo "Ejemplo: $0 10 hsrc-eth0" >&2
    exit 1
fi

if ! command -v tshark &> /dev/null; then
    echo "Error: tshark no encontrado. Instálalo para el análisis."
    exit 1
fi

if ! command -v tcpdump &> /dev/null; then
    echo "Error: tcpdump no encontrado."
    exit 1
fi

# --- MANEJO DE CAPTURA Y ANÁLISIS ---

# Función para detener tcpdump y analizar al presionar Ctrl+C
cleanup() {
    echo -e "\n\n--- Proceso finalizado, iniciando análisis ---"
    
    # Detener la captura si tcpdump sigue corriendo
    if kill $TCPDUMP_PID 2>/dev/null; then
        wait $TCPDUMP_PID 2>/dev/null
    fi
    
    echo "Tasa,Repeticion,Duracion_s,Paquetes,PPS_promedio,BPS_promedio" > "$CSV_FILE"
    
    # ------------------------------------------------------------------
    # ANÁLISIS DE LA CAPTURA GLOBAL USANDO TSHARK
    # ------------------------------------------------------------------
    
    echo "Analizando el archivo $PCAP_FILE..."
    
    TOTAL_PROCESSED_RUNS=0
    CURRENT_TIME_OFFSET=0.0
    
    for valor_rate in "${TAMANYOS_DE_PRUEBA[@]}"; do
        for repeticion in $(seq 0 $((NUM_REPETICIONES - 1))); do
            
            START_TIME=$CURRENT_TIME_OFFSET
            END_TIME=$(echo "$CURRENT_TIME_OFFSET + $DURATION_PER_RUN" | bc)
            
            # FILTRO CRUCIAL: Aislar el tráfico de la ejecución actual por tiempo relativo
            TIME_FILTER="frame.time_relative >= $START_TIME and frame.time_relative < $END_TIME"
            
            # TSHARK: Contar paquetes en ese intervalo
            # -z io,stat es el más sencillo, pero lo haremos manual para mayor simplicidad en el CSV
            
            # Contar paquetes
            PACKETS=$(tshark -r "$PCAP_FILE" -Y "$TIME_FILTER" -T fields -e frame.number 2>/dev/null | wc -l)
            
            # Si se capturó algo, procesar
            if [ "$PACKETS" -gt 0 ]; then
                
                # Obtener estadísticas de I/O para el intervalo
                TSHARK_OUTPUT=$(tshark -r "$PCAP_FILE" -Y "$TIME_FILTER" -z io,stat,0 2>/dev/null)
                
                # Extraer PPS y BPS promedio
                AVG_PPS=$(echo "$TSHARK_OUTPUT" | grep 'Avg Pkts/s' | awk '{print $2}' 2>/dev/null)
                AVG_BPS=$(echo "$TSHARK_OUTPUT" | grep 'Avg Bits/s' | awk '{print $2}' 2>/dev/null)
                
                # Si el análisis de Tshark falla o no encuentra el formato de promedio
                if [ -z "$AVG_PPS" ] || [ -z "$AVG_BPS" ]; then
                    AVG_PPS="N/A"
                    AVG_BPS="N/A"
                fi

                # Guardar en CSV
                echo "$valor_rate,$repeticion,$DURATION_PER_RUN,$PACKETS,$AVG_PPS,$AVG_BPS" >> "$CSV_FILE"
                TOTAL_PROCESSED_RUNS=$((TOTAL_PROCESSED_RUNS + 1))
                
            fi
            
            # Avanzar el offset de tiempo para la siguiente ejecución
            CURRENT_TIME_OFFSET=$END_TIME
            
        done
    done
    
    echo "Se procesaron $TOTAL_PROCESSED_RUNS de 60 ejecuciones esperadas."
    echo "Resultados guardados en: $CSV_FILE"
    
    exit 0
}

# Iniciar la captura en segundo plano
echo "Iniciando captura en la interfaz $INTERFACE..."
echo "Los resultados se guardarán en $PCAP_FILE. Pulse Ctrl+C para detener."
trap cleanup SIGINT

sudo tcpdump -i "$INTERFACE" -n -w "$PCAP_FILE" 2>/dev/null &
TCPDUMP_PID=$!

echo "Ejecute ahora su script de envío: ./tu_script_envio.sh $DURATION_PER_RUN"
echo ""

# Esperar a la señal de interrupción
wait $TCPDUMP_PID

# Si la captura termina por sí misma (lo cual no debería), ejecutar análisis
cleanup
