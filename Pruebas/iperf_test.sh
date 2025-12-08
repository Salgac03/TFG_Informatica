#!/bin/bash

# Este script ejecuta pruebas UDP con iperf.
# 1. BPS: Varía el ancho de banda (Datagrama grande fijo) y calcula la MEDIA.
# 2. PPS: Varía la tasa de paquetes (Datagrama PEQUEÑO fijo).
# Necesita un servidor iperf -s -u activo en el HOST_IP.

# Variables de configuración
ITERATIONS=5        # Número de veces que se repite la prueba para CADA VALOR de parámetro.
TIME_PER_RUN=10     # Duración de cada prueba en segundos (-t)
TEMP_FILE="/tmp/iperf_temp_results.txt" # Archivo temporal para el cálculo de medias

# --- LISTAS DE PARÁMETROS ---
# 1. BPS: Anchos de banda crecientes para medir BPS (con datagrama grande)
BANDWIDTHS_BPS=("100M" "500M" "1G") 
DATAGRAM_SIZE_BPS=1470 # Datagrama grande fijo (cercano al MTU)

# 2. PPS: Tasa de paquetes crecientes para medir PPS (Paquete pequeño fijo)
DATAGRAM_SIZE_PPS=64 # Tamaño de datagrama FIJO en 64 bytes (¡CAMBIO!)
PACKET_RATES_PPS=(64 128 256 512 1024 2048) # Tasa de paquetes de destino (en pps) (¡CAMBIO!)
# -----------------------------


# Verificación de parámetros de entrada
if [[ $# -ne 4 ]]; then
    echo "Uso: $0 <IP_DESTINO> <DURACION_SEG> <FICHERO_BPS> <FICHERO_PPS>"
    echo "Ejemplo: $0 192.168.1.1 10 /tmp/salida_bps.txt /tmp/salida_pps.txt"
    exit 1
fi

DEST_IP="$1"
TIME_PER_RUN="$2"
FILE_BPS="$3"
FILE_PPS="$4"

echo "[*] IP de destino: $DEST_IP | Duración: $TIME_PER_RUN segundos | Iteraciones/Valor: $ITERATIONS"

# Vaciar ficheros de salida y añadir encabezados
# El encabezado de BPS ahora es para la media.
echo "BPS_Media Tiempo_Media Perdida_Media_% Bandwidth_Setting" > "$FILE_BPS" 
# El encabezado de PPS refleja la nueva métrica a variar (Packet_Rate_R)
echo "PPS_Obtenidos Tiempo_Seg Perdida_% Packet_Rate_R_pps" > "$FILE_PPS" 

# Asegurarse de que el archivo temporal no exista al inicio
rm -f "$TEMP_FILE"

---

###############################################################
# FUNCIÓN: Ejecuta iperf UDP y parsea la salida. (Sin cambios)
###############################################################
run_iperf_udp() {
    # El primer parámetro es el ANCHO DE BANDA o la TASA DE PAQUETES
    local traffic_rate_setting="$1"
    local datagram_size="$2"
    local rate_type="$3" # Nuevo: 'BPS' o 'PPS' para saber qué opción de iperf usar

    local iperf_options=""
    if [[ "$rate_type" == "PPS" ]]; then
        # Para PPS, usamos -R (Packet Rate) y NO -b
        iperf_options="-R ${traffic_rate_setting}"
    else
        # Para BPS, usamos -b (Bandwidth)
        iperf_options="-b ${traffic_rate_setting}"
    fi

    # Ejecutar iperf con las opciones determinadas
    OUTPUT=$(iperf -u -c "$DEST_IP" ${iperf_options} -t "$TIME_PER_RUN" -l "$datagram_size" 2>/dev/null)

    # ... (El resto del parsing es el mismo) ...

    LASTLINE=$(echo "$OUTPUT" | grep -E "sec" | tail -1)
    LOSTLINE=$(echo "$OUTPUT" | grep -E "Lost/Total" | tail -1)

    if [[ -z "$LASTLINE" ]]; then
        echo "0 0 0 100" 
        return
    fi

    # 1. Extraer BPS (valor numérico)
    BPS=$(echo "$LASTLINE" | awk '{print $7}' | grep -oE '[0-9]+\.?[0-9]*')
    
    # 2. Extraer PPS (valor numérico)
    PPS=$(echo "$LASTLINE" | awk '{print $9}' | sed 's/pps//' | grep -oE '[0-9]+\.?[0-9]*')

    # 3. Extraer tiempo (valor numérico)
    TIMEVAL=$(echo "$LASTLINE" | awk '{print $3}' | cut -d'-' -f2 | grep -oE '[0-9]+\.?[0-9]*')

    # 4. Extraer pérdida (porcentaje)
    LOSS=$(echo "$LOSTLINE" | awk -F'[()]' '{print $2}' | sed 's/%//' | grep -oE '[0-9]+\.?[0-9]*')
    
    BPS=${BPS:-0}
    PPS=${PPS:-0}
    TIMEVAL=${TIMEVAL:-$TIME_PER_RUN}
    LOSS=${LOSS:-100}

    echo "$BPS" "$PPS" "$TIMEVAL" "$LOSS"
}

---

###############################################################
# FUNCIÓN: CALCULAR Y GUARDAR MEDIA (¡NUEVA!)
###############################################################
calculate_and_save_avg() {
    local setting_value="$1"
    local output_file="$2"

    # Se usa awk para:
    # 1. Sumar las columnas 1 (BPS), 3 (Tiempo) y 4 (Pérdida).
    # 2. Contar el número de líneas (NR).
    # 3. Al final, imprimir el promedio de cada columna.
    AVG_DATA=$(awk -v setting="$setting_value" '
        {
            sum_bps += $1;
            sum_time += $3;
            sum_loss += $4;
        }
        END {
            if (NR > 0) {
                # Columna 1: BPS Media (formato %.2f)
                # Columna 2: Tiempo Media (formato %.2f)
                # Columna 3: Pérdida Media (formato %.2f)
                # Columna 4: El valor de configuración (se pasa como variable setting)
                printf "%.2f %.2f %.2f %s\n", sum_bps/NR, sum_time/NR, sum_loss/NR, setting;
            } else {
                print "0 0 100 " setting;
            }
        }' "$TEMP_FILE")

    echo "$AVG_DATA" >> "$output_file"
    echo "  [✓] MEDIA GUARDADA: BPS: $(echo "$AVG_DATA" | awk '{print $1}') | Pérdida: $(echo "$AVG_DATA" | awk '{print $3}')%"
    
    # Borrar el archivo temporal para la siguiente configuración
    rm -f "$TEMP_FILE"
}

---

###############################################################
# 1. PRUEBAS DE BITS POR SEGUNDO (BPS) CON MEDIA
###############################################################
echo "[*] Iniciando pruebas de BPS, variando el Ancho de Banda (Datagrama Fijo: ${DATAGRAM_SIZE_BPS}B). Calculando Media..."

for bandwidth in "${BANDWIDTHS_BPS[@]}"; do
    echo "--- BPS | Configuración: Bandwidth = $bandwidth ---"
    
    for i in $(seq 1 $ITERATIONS); do
        
        # Ejecutar iperf para BPS. El tipo es "BPS".
        read BPS PPS TIMEVAL LOSS < <(run_iperf_udp "$bandwidth" "$DATAGRAM_SIZE_BPS" "BPS") 
        
        # Guardar BPS, PPS, Tiempo, Pérdida en el archivo temporal para el cálculo de la media (¡CAMBIO!)
        echo "$BPS $PPS $TIMEVAL $LOSS" >> "$TEMP_FILE"
        
        echo "  Guardado temporal BPS: $BPS | Ejecución $i | Pérdida: $LOSS%"
    done
    
    # Después de las iteraciones, calcular y guardar la media (¡CAMBIO!)
    calculate_and_save_avg "$bandwidth" "$FILE_BPS"
done

---

###############################################################
# 2. PRUEBAS DE PAQUETES POR SEGUNDO (PPS) - TASA DE PAQUETES VARIABLE
###############################################################
echo "[*] Iniciando pruebas de PPS, variando la TASA DE PAQUETES (Datagrama Fijo: ${DATAGRAM_SIZE_PPS}B)..."

# Iteramos sobre la nueva lista de tasas de paquetes
for rate in "${PACKET_RATES_PPS[@]}"; do
    echo "--- PPS | Configuración: Packet Rate = ${rate} pps ---"
    
    for i in $(seq 1 $ITERATIONS); do
        
        # Ejecutar iperf para PPS. Usamos -R para la tasa de paquetes y el tipo es "PPS" (¡CAMBIO!)
        read BPS PPS TIMEVAL LOSS < <(run_iperf_udp "$rate" "$DATAGRAM_SIZE_PPS" "PPS")
        
        # Guardar PPS, Tiempo, Pérdida y la tasa de paquetes configurada (¡CAMBIO!)
        echo "$PPS $TIMEVAL $LOSS $rate" >> "$FILE_PPS"

        echo "  Guardado PPS: $PPS | Ejecución $i | Tasa configurada: ${rate} pps | Pérdida: $LOSS%"
    done
done

echo ""
echo "[✓] PRUEBAS UDP COMPLETADAS."
echo "[*] Resultados BPS → $FILE_BPS (Media por Ancho de Banda)"
echo "[*] Resultados PPS → $FILE_PPS (Varía Tasa de Paquetes)"
