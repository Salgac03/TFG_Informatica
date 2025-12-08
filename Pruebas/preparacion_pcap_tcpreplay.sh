#!/bin/bash

# $1: MAC de Origen (SMAC)
# $2: MAC de Destino (DMAC)
# $3: IP de Destino (IP_D)
# $4: Archivo PCAP Original

MAC_ORIGEN="$1"
MAC_DESTINO="$2"
IP_DESTINO="$3"
ARCHIVO_ORIGINAL="$4"

# Usamos basename para asegurar nombres de archivo limpios
NOMBRE_BASE=$(basename "$ARCHIVO_ORIGINAL")
ARCHIVO_RECORTADO="cut_${NOMBRE_BASE}"
ARCHIVO_FINAL_PRUEBA="final_test_${NOMBRE_BASE}"

# Limite de paquetes para el recorte
LIMITE_PAQUETES=100000

# -------------------------------------------------------------------------
# 1. VERIFICACIÓN DE PARÁMETROS
# -------------------------------------------------------------------------

if [ -z "$ARCHIVO_ORIGINAL" ] || [ -z "$IP_DESTINO" ]; then
    echo "ERROR: Uso: $0 <MAC_O> <MAC_D> <IP_D> <Archivo.pcap>"
    exit 1
fi

if [ ! -f "$ARCHIVO_ORIGINAL" ]; then
    echo "ERROR: Archivo original no encontrado: $ARCHIVO_ORIGUAL"
    exit 1
fi

# -------------------------------------------------------------------------
# 2. RECORTAR Y NORMALIZAR CON TSHARK (USANDO -Y)
# -------------------------------------------------------------------------
echo "Recortando y normalizando a $LIMITE_PAQUETES paquetes..."

# Corrección: Cambiado -R por -Y para compatibilidad con la versión moderna de tshark.
# Filtra por "eth" (Ethernet) para normalizar la cabecera.
tshark -r "$ARCHIVO_ORIGINAL" -c "$LIMITE_PAQUETES" -Y "eth" -w "$ARCHIVO_RECORTADO"

if [ $? -ne 0 ]; then
    echo "ERROR: Falló el recorte/normalización con tshark. El filtro o la sintaxis es incorrecta."
    rm -f "$ARCHIVO_RECORTADO"
    exit 1
fi

# -------------------------------------------------------------------------
# 3. REESCRITURA CON TCPREWRITE
# -------------------------------------------------------------------------
echo "Reescribiendo direcciones..."

tcprewrite \
    --enet-smac="$MAC_ORIGEN" \
    --enet-dmac="$MAC_DESTINO" \
    --dstipmap=0.0.0.0/"$IP_DESTINO" \
    --infile="$ARCHIVO_RECORTADO" \
    --outfile="$ARCHIVO_FINAL_PRUEBA"

REWRITE_STATUS=$?

# -------------------------------------------------------------------------
# 4. LIMPIEZA Y FINALIZACIÓN
# -------------------------------------------------------------------------
rm -f "$ARCHIVO_RECORTADO"

if [ $REWRITE_STATUS -ne 0 ]; then
    echo "ERROR: Falló la reescritura con tcprewrite."
    rm -f "$ARCHIVO_FINAL_PRUEBA"
    exit 1
fi

echo "Proceso completado. Archivo final: $ARCHIVO_FINAL_PRUEBA"
