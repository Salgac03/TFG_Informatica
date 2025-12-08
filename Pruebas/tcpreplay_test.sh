#!/bin/bash

# $1: MAC de Origen
# $2: MAC de Destino
# $3: IP de Destino
# $4: Archivo PCAP Original

MAC_ORIGEN="$1"
MAC_DESTINO="$2"
IP_DESTINO="$3"
ARCHIVO_ORIGINAL="$4"

ARCHIVO_FINAL_PRUEBA="final_test_${ARCHIVO_ORIGINAL}"

INTERFAZ_SALIDA="eth0"
LIMITE_PAQUETES=100000

tamanyos_de_prueba=(64 128 256 512 1024 2048)
NUM_REPETICIONES=10

if [ -z "$ARCHIVO_ORIGINAL" ] || [ -z "$IP_DESTINO" ]; then
    echo "Uso: $0 <MAC_O> <MAC_D> <IP_D> <Archivo.pcap>"
    echo "El script usa un límite fijo de $LIMITE_PAQUETES paquetes para la prueba."
    exit 1
fi

tcprewrite \
    --enet-smac="$MAC_ORIGEN" \
    --enet-dmac="$MAC_DESTINO" \
    --dstipmap=0.0.0.0/"$IP_DESTINO" \
    --infile="$ARCHIVO_ORIGINAL" \
    --outfile="$ARCHIVO_FINAL_PRUEBA"

if [ $? -ne 0 ]; then
    echo "ERROR: Falló la reescritura con tcprewrite."
    exit 1
fi

# =======================================================
#               DOBLE BUCLE 1: PRUEBAS PPS
# =======================================================
for valor_a in "${tamanyos_de_prueba[@]}"; do
    
    for repeticion_a in $(seq 0 $((NUM_REPETICIONES - 1))); do
        
        tcpreplay -i "$INTERFAZ_SALIDA" --pps="$valor_a" "$ARCHIVO_FINAL_PRUEBA"
        
    done
    
done

# =======================================================
#               DOBLE BUCLE 2: PRUEBAS MBPS (BPS)
# =======================================================
for valor_b in "${tamanyos_de_prueba[@]}"; do
    
    for repeticion_b in $(seq 0 $((NUM_REPETICIONES - 1))); do
        
        tcpreplay -i "$INTERFAZ_SALIDA" --mbps="$valor_b" "$ARCHIVO_FINAL_PRUEBA"
        
    done
    
done

# LIMPIEZA
rm -f "$ARCHIVO_RECORTADO" "$ARCHIVO_FINAL_PRUEBA"
