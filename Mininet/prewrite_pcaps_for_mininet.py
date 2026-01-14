#!/usr/bin/env python3
"""prewrite_pcaps_for_mininet.py

Reescribe PCAPs grandes (legit/malign) UNA SOLA VEZ para que encajen en tu entorno Mininet:
- Ajusta MAC origen/destino a las MAC reales de hsrc/hdst en SimpleTopo
- Recalcula checksums (--fixcsum)
- Genera nuevos ficheros *_mininet.pcap listos para usar con tcpreplay SIN tcprewrite

IMPORTANTE:
- Esto NO ejecuta tests, NO XDP, NO iperf. Solo prepara PCAPs.
- Requiere tcprewrite instalado.
- Se arranca Mininet un momento SOLO para leer las MACs reales (hsrc/hdst).
  (Luego se para.)

Uso recomendado (PCAPs en ruta absoluta):
  sudo python3 prewrite_pcaps_for_mininet.py --repo-root /RUTA/REPO \
      -l /RUTA/ABS/Legitimo.pcap -m /RUTA/ABS/CryLock_24012021.pcap

Opcional:
  --out-dir /RUTA/SALIDA   (por defecto crea /tmp/pcaps_mininet_<tag>/)

Salida:
  out-dir/legit_mininet.pcap
  out-dir/malign_mininet.pcap
  out-dir/metadata.txt (MACs usadas + comandos ejecutados)

Luego en tus tests:
  tcpreplay ... legit_mininet.pcap
  tcpreplay ... malign_mininet.pcap
"""

import argparse
import os
import shlex
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

from redarbolrw1 import SimpleTopo


def now_tag():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def must_exist(path: str, what: str):
    if not os.path.isfile(path):
        raise SystemExit(f"[FATAL] {what} no existe: {path}")


def run_cmd(host, cmd: str) -> str:
    return host.cmd(cmd)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Ejecuta con sudo.")

    ap = argparse.ArgumentParser(description="Reescribe PCAPs para Mininet (MACs + fixcsum) una sola vez.")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("-l", "--legit", dest="pcap_legit", required=True)
    ap.add_argument("-m", "--malign", dest="pcap_malign", required=True)
    ap.add_argument("--out-dir", default=None)
    args = ap.parse_args()

    pcap_legit = abspath(args.repo_root, args.pcap_legit)
    pcap_malign = abspath(args.repo_root, args.pcap_malign)
    must_exist(pcap_legit, "PCAP legítimo")
    must_exist(pcap_malign, "PCAP maligno")

    out_dir = args.out_dir or f"/tmp/pcaps_mininet_{now_tag()}"
    os.makedirs(out_dir, exist_ok=True)

    out_legit = os.path.join(out_dir, "legit_mininet.pcap")
    out_malign = os.path.join(out_dir, "malign_mininet.pcap")
    meta = os.path.join(out_dir, "metadata.txt")

    print(f"[PREWRITE] out_dir={out_dir}")
    print(f"[PREWRITE] legit_in={pcap_legit}")
    print(f"[PREWRITE] malign_in={pcap_malign}")

    net = Mininet(topo=SimpleTopo(), controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)
    net.start()
    try:
        hsrc, hdst = net["hsrc"], net["hdst"]
        smac = hsrc.MAC()
        dmac = hdst.MAC()
        tx_iface = hsrc.defaultIntf().name
        rx_iface = hdst.defaultIntf().name

        print(f"[PREWRITE] Detectadas MACs Mininet: smac={smac} dmac={dmac}")
        print(f"[PREWRITE] Ifaces (por info): tx={tx_iface} rx={rx_iface}")

        cmd_legit = (
            f"tcprewrite --enet-smac={smac} --enet-dmac={dmac} --fixcsum "
            f"--infile={shlex.quote(pcap_legit)} --outfile={shlex.quote(out_legit)}"
        )
        print("[PREWRITE] Reescribiendo legit (puede tardar con 2GB)...")
        out = run_cmd(hsrc, f"{cmd_legit}; echo $?").strip().splitlines()
        rc_legit = out[-1] if out else "99"

        cmd_malign = (
            f"tcprewrite --enet-smac={smac} --enet-dmac={dmac} --fixcsum "
            f"--infile={shlex.quote(pcap_malign)} --outfile={shlex.quote(out_malign)}"
        )
        print("[PREWRITE] Reescribiendo malign (puede tardar con 1.5GB)...")
        out = run_cmd(hsrc, f"{cmd_malign}; echo $?").strip().splitlines()
        rc_malign = out[-1] if out else "99"

        with open(meta, "w") as f:
            f.write(f"timestamp={datetime.now().isoformat(timespec='seconds')}\n")
            f.write(f"smac={smac}\n")
            f.write(f"dmac={dmac}\n")
            f.write(f"tx_iface={tx_iface}\n")
            f.write(f"rx_iface={rx_iface}\n\n")
            f.write(f"cmd_legit={cmd_legit}\n")
            f.write(f"rc_legit={rc_legit}\n")
            f.write(f"cmd_malign={cmd_malign}\n")
            f.write(f"rc_malign={rc_malign}\n")

        print(f"[PREWRITE] rc_legit={rc_legit}  -> {out_legit}")
        print(f"[PREWRITE] rc_malign={rc_malign} -> {out_malign}")
        print(f"[PREWRITE] metadata -> {meta}")

    finally:
        net.stop()

    print("[PREWRITE] listo.")


if __name__ == "__main__":
    setLogLevel("info")
    main()
