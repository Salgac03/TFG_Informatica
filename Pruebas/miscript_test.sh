#!/bin/bash

# Este script ahora recibe SOLO el tiempo (duration) como parámetro de entrada.
# Uso: ./nombre_del_script.sh <duration>

# 1. Asignar el parámetro de entrada
# El primer argumento ($1) es la duración (tiempo)
duration=$1

# Comprobar que se ha proporcionado el argumento
if [ -z "$duration" ]; then
    echo "Uso: $0 <duration>" >&2
    echo "Ejemplo: $0 60" >&2
    exit 1
fi

# 2. Array con los valores de velocidad (fijo, sin usar parámetros)
tamanyos_de_prueba=(64 128 256 512 1024 2048 4096 8192 10000 15000 20000)

source ../../env_tfg/bin/activate

NUM_REPETICIONES=10

# =======================================================
#                  DOBLE BUCLE
# =======================================================
# LÍNEA CORREGIDA: Usar el nombre de variable correcto: tamanyos_de_prueba
for valor_rate in "${tamanyos_de_prueba[@]}"; do
    
    for repeticion in $(seq 0 $((NUM_REPETICIONES - 1))); do
        
        # Ejecución del comando principal
        python3 ../Mininet/trafico_eth.py -m ../../CryLock_24012021.pcap -l ../../Legitimo.pcap --src_mac 00:00:00:00:01:01 --dst_mac 00:00:00:00:02:02 --rate ${valor_rate} --duration ${duration} --iface hsrc-eth0
    done
    
done
