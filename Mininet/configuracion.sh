#!/bin/bash

# Función para desactivar Docker
desactivar_docker() {
  echo "Desactivando Docker..."
  sudo systemctl stop docker.service
  sudo systemctl stop docker.socket
  sudo systemctl disable docker.socket
  echo "Docker desactivado."
}

# Función para activar Docker
activar_docker() {
  echo "Activando Docker..."
  sudo systemctl enable docker.socket
  sudo systemctl start docker.service
  echo "Docker activado."
}

# Función para eliminar la regla de iptables
eliminar_regla_iptables() {
  echo "Buscando y eliminando regla de iptables..."
  # Buscar la regla de DROP
  numero_linea=$(sudo iptables -L FORWARD --line-numbers | grep "DROP.*10.0.0.0/8" | awk '{print $1}')
  if [ -n "$numero_linea" ]; then
    sudo iptables -D FORWARD "$numero_linea"
    echo "Regla de iptables eliminada."
  else
    echo "No se encontró la regla de iptables."
  fi
}

# Menú principal
while true; do
  echo "Selecciona una opción:"
  echo "1. Desactivar Docker y eliminar regla de iptables"
  echo "2. Activar Docker"
  echo "3. Salir"
  read opcion

  case $opcion in
  1)
    desactivar_docker
    eliminar_regla_iptables
    ;;
  2)
    activar_docker
    ;;
  3)
    break
    ;;
  *)
    echo "Opción inválida."
    ;;
  esac
done

echo "Script finalizado."
