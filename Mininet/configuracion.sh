#!/bin/bash

# Este script pretende instalar mininet en el equipo
# Toda la información de como instalar mininet en https://mininet.org/download/

echo 'Introduce el nombre del directorio en el que quieres instalar mininet (no añadir mininet al final ni nada, solo el directorio ya existente): '
read PATH

if ![[ -d $PATH ]]
then
	echo 'El directorio proporcionado no existe'
	exit
fi

if [[ $(stat -c "%a" "$DIR") -lt 700 && $EUID -ne 0 ]]
then
	echo 'Para modificar el directorio proporcionado se necesitan permisos de superusuario'
	echo 'Ejecute el script de nuevo con sudo'
	exit
fi

cd $PATH
mkdir aux_tmp
cd aux_tmp

git clone https://github.com/mininet/mininet

cd mininet
git tag  # list available versions
git checkout -b mininet-2.3.0 2.3.0  # or whatever version you wish to install
cd ..

mininet/util/install.sh -s $PATH -nfv

cd $PATH
rm -rdf aux_tmp
