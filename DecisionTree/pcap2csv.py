'''
Script python que transforma un archivo .pcap en uno .csv con
el fin de facilitar entrenamientos de árboles de decisión de redes,
a parte le añade una columna extra como clasificador

En esta versión inical no se tiene en cuenta la capa de aplicación.
'''

from scapy.all import PcapReader, Ether, IP, TCP, UDP, Packet
import pandas as pd
import sys
import csv
from typing import Dict, Any


def paqt2dict(paqt : Packet) -> Dict[str, Any]:
    '''Función que convierte un paquete en un diccionario'''
    dic = {}

    dic["size"] = len(paqt)


    if paqt.haslayer(Ether):
       dic["eth_src"] = paqt[Ether].src 
       dic["eth_dst"] = paqt[Ether].dst 
       dic["eth_type"] = paqt[Ether].type
    else:
       dic["eth_src"] = None 
       dic["eth_dst"] = None 
       dic["eth_type"] = None 
        

    if paqt.haslayer(IP):
        dic["ip_src"] = paqt[IP].src
        dic["ip_dst"] = paqt[IP].dst
        dic["ip_proto"] = paqt[IP].proto
        dic["ip_ttl"] = paqt[IP].ttl
    else: 
        dic["ip_src"] = None 
        dic["ip_dst"] = None
        dic["ip_proto"] = None 
        dic["ip_ttl"] = None


    if paqt.haslayer(TCP):
        dic["protocolo_IP"] = "TCP"
        dic["src_port"] = paqt[TCP].sport
        dic["dst_port"] = paqt[TCP].dport
        dic["tcp_flags"] = paqt[TCP].flags
    elif paqt.haslayer(UDP):
        dic["protocolo_IP"] = "UDP"
        dic["src_port"] = paqt[UDP].sport
        dic["dst_port"] = paqt[UDP].dport
        dic["tcp_flags"] = None

    return dic


def main():
    if len(sys.argv) != 3:
        print("Introduce como parámetro el nombre del archivo pcap ransomware y el archivo con trafico normal que quieres convertir a csv en el orden dicho.")
        return -1


    # Nombre del archivo csv final
    csv_filename = sys.argv[1].replace(".pcap", ".csv")

    # Abrimos el archivo pcap y lo vamos convirtiendo a csv
    try:
        # Array de diccionarios que se transforman en la parte del csv 
        # correspondiente al ransomware
        datos = []
        i = 0

        with PcapReader(sys.argv[1]) as paquetes:

            for paqt in paquetes:
                dic = paqt2dict(paqt)

                dic["Ransomware"] = "Yes"

                datos.append(dic)
                i += 1

                if i == 1024:
                    with open(csv_filename, mode='a', newline='') as csv_file:
                        writer = csv.DictWriter(csv_file, fieldnames=datos[0].keys())
                        if csv_file.tell() == 0:
                            writer.writeheader()

                        writer.writerows(datos)


                    datos = []
                    i = 0


        if datos:
            with open(csv_filename, mode='a', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=datos[0].keys())

                writer.writerows(datos)


    except Exception as e:
        print(f"Error al abrir y leer el archivo pcap ransomware y pasarlo a csv. Ha saltado la excepción: {e}")
        return -1


    # Abrimos el archivo pcap y lo vamos convirtiendo a csv
    try:
        # Array de diccionarios que se transforman en la parte del csv 
        # correspondiente a los datos para hacer un balanceo de clases 
        datos = []
        i = 0

        with PcapReader(sys.argv[2]) as paquetes:

            for paqt in paquetes:
                dic = paqt2dict(paqt)

                dic["Ransomware"] = "No"

                datos.append(dic)
                i += 1

                if i == 1024:
                    with open(csv_filename, mode='a', newline='') as csv_file:
                        writer = csv.DictWriter(csv_file, fieldnames=datos[0].keys())
                        writer.writerows(datos)


                    datos = []
                    i = 0


        if datos:
            with open(csv_filename, mode='a', newline='') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=datos[0].keys())

                writer.writerows(datos)


    except Exception as e:
        print(f"Error al abrir y leer el archivo pcap de balanceo de clases y pasarlo a csv. Ha saltado la excepción: {e}")
        return -1



if __name__ == '__main__':
    main()
