#!/bin/bash

# Este script pretende instalar Mininet en el equipo
# Toda la información de como instalar mininet en https://mininet.org/download/

echo 'Introduce el nombre del directorio en el que quieres instalar Mininet (no añadir mininet al final ni nada, solo el directorio ya existente): '
read DIR

# Verificar si el directorio existe
if ! [[ -d "$DIR" ]]; then
    echo 'El directorio proporcionado no existe.'
    exit 1
fi

# Verificar permisos
if [[ $(stat -c "%a" "$DIR") -lt 700 && $EUID -ne 0 ]]; then
    echo 'Para modificar el directorio proporcionado se necesitan permisos de superusuario.'
    echo 'Ejecute el script de nuevo con sudo.'
    exit 1
fi

# Verificar si git está instalado
if ! command -v git &> /dev/null; then
    echo 'Git no está instalado. Instalando git...'
    sudo apt update && sudo apt install git -y
fi

# Continuar con la instalación de Mininet
cd "$DIR" || exit 1
mkdir -p aux_tmp
cd aux_tmp || exit 1

# Clonar el repositorio de Mininet
git clone https://github.com/mininet/mininet

cd mininet || exit 1
git tag  # Muestra las versiones disponibles
git checkout -b mininet-2.3.0 2.3.0  # O usa la versión que desees
cd ..

# Instalar Mininet
mininet/util/install.sh -s "$DIR" -nfv

# Limpieza
#cd "$DIR" || exit 1
#rm -rf aux_tmp

echo 'Mininet instalado correctamente.'
