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
from typing import Dict, Any

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
    "ip_tot_len",
    "ip_id",
    "ip_frag_flags",
    "ip_frag_offset",
    "src_port",
    "dst_port",
    "tcp_seq",
    "tcp_ack",
    "tcp_window",
    "tcp_flags",
    "timestamp",
    "Ransomware"
]

def paqt2dict(paqt: Packet) -> Dict[str, Any]:
    '''Función que convierte un paquete en un diccionario con las características extraídas.'''
    dic = {}

    try:
        packet = Ether(paqt) if isinstance(paqt, bytes) else paqt
    except Exception as e:
        print(f"Error al procesar el paquete: {e}")
        return {}

    # Tamaño total del paquete
    dic["size"] = len(packet)

    # Capa Ethernet
    if packet.haslayer(Ether):
        dic["eth_src"] = packet[Ether].src
        dic["eth_dst"] = packet[Ether].dst
        dic["eth_type"] = packet[Ether].type
    else:
        dic["eth_src"] = None
        dic["eth_dst"] = None
        dic["eth_type"] = None

    # Capa IP
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        dic["ip_src"] = ip_layer.src
        dic["ip_dst"] = ip_layer.dst
        dic["ip_proto"] = ip_layer.proto
        dic["ip_ttl"] = ip_layer.ttl
        dic["ip_tot_len"] = ip_layer.len
        dic["ip_id"] = ip_layer.id
        dic["ip_frag_flags"] = ip_layer.flags
        dic["ip_frag_offset"] = ip_layer.frag
    else:
        dic["ip_src"] = None
        dic["ip_dst"] = None
        dic["ip_proto"] = None
        dic["ip_ttl"] = None
        dic["ip_tot_len"] = None
        dic["ip_id"] = None
        dic["ip_frag_flags"] = None
        dic["ip_frag_offset"] = None

    # Capa TCP o UDP
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        dic["src_port"] = tcp_layer.sport
        dic["dst_port"] = tcp_layer.dport
        dic["tcp_seq"] = tcp_layer.seq
        dic["tcp_ack"] = tcp_layer.ack
        dic["tcp_window"] = tcp_layer.window
        dic["tcp_flags"] = tcp_layer.flags
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        dic["src_port"] = udp_layer.sport
        dic["dst_port"] = udp_layer.dport
        dic["tcp_seq"] = None
        dic["tcp_ack"] = None
        dic["tcp_window"] = None
        dic["tcp_flags"] = None
    else:
        dic["src_port"] = None
        dic["dst_port"] = None
        dic["tcp_seq"] = None
        dic["tcp_ack"] = None
        dic["tcp_window"] = None
        dic["tcp_flags"] = None

    # Metadata adicional
    dic["timestamp"] = paqt.time if hasattr(paqt, "time") else None

    return dic


def process_pcap(filename: str, label: str):
    """Procesa un archivo .pcap y genera un CSV con los datos extraídos."""
    try:
        datos = []
        i = 0
        first_chunk = True

        with PcapReader(filename) as paquetes:
            for paqt in paquetes:
                dic = paqt2dict(paqt)
                dic["Ransomware"] = label
                datos.append(dic)
                i += 1

                if i == 1024:  # Escribir en chunks para manejar archivos grandes
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
        print(f"Error al procesar el archivo .pcap: {e}")
        return -1


def main():
    parser = argparse.ArgumentParser(description="Script para procesar archivos .pcap y generar un dataset.")
    parser.add_argument('-m', '--mfiles', nargs='+', help='Archivos .pcap etiquetados como ransomware', required=True)
    parser.add_argument('-l', '--lfiles', nargs='+', help='Archivos .pcap etiquetados como legítimos', required=True)
    args = parser.parse_args()

    # Crear el archivo CSV con el encabezado una vez
    with open(csv_filename, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

    # Procesar los archivos de ransomware
    for file in args.mfiles:
        process_pcap(file, "Yes")

    # Procesar los archivos legítimos
    for file in args.lfiles:
        process_pcap(file, "No")


if __name__ == '__main__':
    main()
