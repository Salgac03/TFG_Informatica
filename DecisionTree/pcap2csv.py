'''
Script python que transforma un archivo .pcap en uno .csv con
el fin de facilitar entrenamientos de árboles de decisión de redes,
a parte le añade una columna extra como clasificador

En esta versión inical no se tiene en cuenta la capa de aplicación.
'''

from scapy.all import PcapReader, Ether, IP, TCP, UDP, Packet
import sys
import csv
import argparse
from typing import Dict, Any, Tuple


csv_filename = './dataset.csv'
fieldnames = [
    "size",
    "eth_src",
    "eth_dst",
    "eth_type",
    "ip_src",
    "ip_dst",
    "ip_proto",
    "ip_ttl",
    "protocolo_IP",
    "src_port",
    "dst_port",
    "tcp_flags",
    "Ransomware"
]

def paqt2dict(paqt: Packet | Tuple) -> Dict[str, Any]:
    '''Función que convierte un paquete (o tuple) en un diccionario'''
    dic = {}

    if isinstance(paqt, tuple):
        # Assuming the first element of the tuple is the raw packet data
        if paqt:
            try:
                packet = Ether(paqt[0])
            except Exception as e:
                print(f"Error al crear el paquete Scapy desde la tupla: {e}")
                return {} # Return an empty dict or handle error as needed
        else:
            return {} # Empty tuple, return empty dict
    elif isinstance(paqt, Packet):
        packet = paqt
    else:
        print(f"Tipo de paquete no reconocido: {type(paqt)}")
        return {} # Return empty dict for unknown types

    dic["size"] = len(packet)

    if packet.haslayer(Ether):
        dic["eth_src"] = packet[Ether].src
        dic["eth_dst"] = packet[Ether].dst
        dic["eth_type"] = packet[Ether].type
    else:
        dic["eth_src"] = None
        dic["eth_dst"] = None
        dic["eth_type"] = None

    if packet.haslayer(IP):
        dic["ip_src"] = packet[IP].src
        dic["ip_dst"] = packet[IP].dst
        dic["ip_proto"] = packet[IP].proto
        dic["ip_ttl"] = packet[IP].ttl
    else:
        dic["ip_src"] = None
        dic["ip_dst"] = None
        dic["ip_proto"] = None
        dic["ip_ttl"] = None

    if packet.haslayer(TCP):
        dic["protocolo_IP"] = "TCP"
        dic["src_port"] = packet[TCP].sport
        dic["dst_port"] = packet[TCP].dport
        dic["tcp_flags"] = packet[TCP].flags
    elif packet.haslayer(UDP):
        dic["protocolo_IP"] = "UDP"
        dic["src_port"] = packet[UDP].sport
        dic["dst_port"] = packet[UDP].dport
        dic["tcp_flags"] = None
    else:
        dic["protocolo_IP"] = None
        dic["src_port"] = None
        dic["dst_port"] = None
        dic["tcp_flags"] = None

    return dic



def paqt_ransomware(filename : str):
    try:
        # Array de diccionarios que se transforman en la parte del csv
        # correspondiente al ransomware
        datos = []
        i = 0
        first_chunk = True

        with PcapReader(filename) as paquetes:
            for paqt in paquetes:
                dic = paqt2dict(paqt)
                dic["Ransomware"] = "Yes"
                datos.append(dic)
                i += 1

                if i == 1024:
                    with open(csv_filename, mode='a', newline='') as csv_file:
                        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                        if first_chunk and csv_file.tell() == 0:
                            writer.writeheader()
                            first_chunk = False
                        writer.writerows(datos)
                    datos = []
                    i = 0

        # Escribir los datos restantes si hay menos de 1024 paquetes
        if datos:
            with open(csv_filename, mode='a', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                if first_chunk and csv_file.tell() == 0:
                    writer.writeheader()
                writer.writerows(datos)

    except Exception as e:
        print(f"Error al abrir y leer el archivo pcap ransomware y pasarlo a csv. Ha saltado la excepción: {e}")
        return -1



def paqt_legitimo(filename : str):
    # Abrimos el archivo pcap y lo vamos convirtiendo a csv
    try:
        # Array de diccionarios que se transforman en la parte del csv
        # correspondiente a los datos para hacer un balanceo de clases
        datos = []
        i = 0
        first_chunk = True

        with PcapReader(filename) as paquetes:
            for paqt in paquetes:
                dic = paqt2dict(paqt)
                dic["Ransomware"] = "No"
                datos.append(dic)
                i += 1

                if i == 1024:
                    with open(csv_filename, mode='a', newline='') as csv_file:
                        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                        if first_chunk and csv_file.tell() == 0:
                            writer.writeheader()
                            first_chunk = False
                        writer.writerows(datos)
                    datos = []
                    i = 0

        # Escribir los datos restantes si hay menos de 1024 paquetes
        if datos:
            with open(csv_filename, mode='a', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                if first_chunk and csv_file.tell() == 0:
                    writer.writeheader()
                writer.writerows(datos)

    except Exception as e:
        print(f"Error al abrir y leer el archivo pcap de balanceo de clases y pasarlo a csv. Ha saltado la excepción: {e}")
        return -1


def main():
    parser = argparse.ArgumentParser(description="Procesar archivos con -m y -l. Ambas opciones son obligatorias.")

    # Definir los argumentos -m y -l que aceptan múltiples valores
    parser.add_argument('-m', '--mfiles', nargs='+', help='Lista de archivos para la opción -m', required=True)
    parser.add_argument('-l', '--lfiles', nargs='+', help='Lista de archivos para la opción -l', required=True)

    # Parsear los argumentos
    args = parser.parse_args()

    # Acceder a los valores de los argumentos
    mfiles = args.mfiles  # Archivos pasados con la opción -m
    lfiles = args.lfiles

    # Escribir el encabezado del CSV solo una vez al principio
    with open(csv_filename, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

    for file in mfiles:
        paqt_ransomware(file)

    for file in lfiles:
        paqt_legitimo(file)



if __name__ == '__main__':
    main()
