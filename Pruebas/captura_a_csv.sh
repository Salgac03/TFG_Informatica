#!/bin/bash

# El nombre del archivo CSV es el primer argumento
OUTPUT_FILE=$1

# --- Función para detener la captura de forma segura (Manejo de Ctrl+C) ---
cleanup() {
    # El proceso de tcpdump está en segundo plano, lo matamos.
    # El PID se captura dentro de la subshell que lanza la captura.
    echo -e "\nFinalizando captura..."
    # Se usa 'killall' para buscar y matar cualquier proceso 'tcpdump' que aún esté corriendo
    # que haya sido lanzado por el script (más seguro que confiar en un PID si falla el trap).
    sudo pkill -SIGINT -f "tcpdump -n -tttt -q -i any" 2>/dev/null
    
    echo "Captura finalizada. El archivo CSV se ha guardado en: $OUTPUT_FILE"
    exit 0
}

# Asociar la función cleanup a la señal de interrupción (Ctrl+C)
trap cleanup SIGINT

# --- Verificaciones ---

if [ -z "$OUTPUT_FILE" ]; then
    echo "Error: Debes proporcionar el nombre del archivo CSV como argumento."
    echo "Uso: $0 <nombre_del_archivo.csv>"
    exit 1
fi

if ! command -v tcpdump &> /dev/null; then
    echo "Error: El comando 'tcpdump' no se encontró."
    exit 1
fi

# --- Ejecución ---

echo "Iniciando la captura continua de paquetes..."
echo "Es posible que se solicite la contraseña de sudo para ejecutar tcpdump."
echo "Press Ctrl+C para detener la captura y generar el archivo CSV."

# Definir la cabecera del CSV
echo "Timestamp,Interface,Source_IP:Port,Destination_IP:Port,Protocol,Length" > "$OUTPUT_FILE"

# Iniciar tcpdump y redirigir su salida directamente al archivo CSV
# -i any: Interfaz cualquiera
# -n: No resolver nombres de host (más rápido y mejor para análisis)
# -tttt: Añadir marca de tiempo con formato completo (YYYY-MM-DD HH:MM:SS.frac)
# -q: Salida tranquila (menos verborrea)
# -l: Asegura que la salida sea "line-buffered", lo que ayuda a la redirección en tiempo real.
# >> $OUTPUT_FILE: Agrega la salida al archivo.

sudo tcpdump -n -tttt -q -l -i any >> "$OUTPUT_FILE" 2>/dev/null &
TCPDUMP_PID=$!

# Esperar indefinidamente, permitiendo que el trap SIGINT (Ctrl+C) funcione.
wait $TCPDUMP_PID

# Si el wait termina (lo cual no debería ocurrir salvo error), llamamos a cleanup.
cleanup
