#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""script_reenvio_v4.py

Preparación + envío (PCAP auxiliar) alineado con el estilo de tcpreplay que te
funciona en run_experiments_v4.

Cambios clave vs v3:
- Invocación tcpreplay "simple": --pps=<int> --limit=<N> (sin --pps-multi, sin --loop).
- Envolvemos tcpreplay con timeout para no quedarnos colgados.
- PCAP temporal preferentemente en /dev/shm (tmpfs) para evitar I/O en disco.
- Escritura del PCAP con PcapWriter(sync=False) (mucho más rápido al preparar).

Uso:
  sudo python3 script_reenvio_v4.py --legit legit.pcap --mal mal.pcap --iface hsrc-eth0 --pps 15000 --duration 10 --seed 123
"""

import argparse
import math
import os
import random
import subprocess
import tempfile
from dataclasses import dataclass


@dataclass
class Sources:
    legit: str
    mal: str


def pick_tcpreplay_cache_flag() -> str | None:
    """Devuelve el flag de cache en RAM soportado por tcpreplay."""
    try:
        help_txt = subprocess.run(
            ["tcpreplay", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        ).stdout
    except Exception:
        return None

    if "--enable-file-cache" in help_txt:
        return "--enable-file-cache"
    if "--preload-pcap" in help_txt:
        return "--preload-pcap"
    if " -K," in help_txt or "-K " in help_txt:
        return "-K"
    return None


def run_tcpreplay_once(
    iface: str,
    pcap_path: str,
    pps: int,
    packets: int,
    duration_s: float,
    stats_interval: int,
    enable_file_cache: bool,
    dry_run: bool,
) -> None:
    # Alineado con run_experiments_v4: tcpreplay --intf1=<iface> --pps=<int> --limit=<N> <pcap>
    cmd = [
        "timeout",
        str(int(math.ceil(duration_s)) + 3),
        "tcpreplay",
        "--intf1",
        iface,
        "--pps",
        str(int(pps)),
        "--limit",
        str(int(packets)),
    ]

    if stats_interval and stats_interval > 0:
        cmd += ["--stats", str(int(stats_interval))]

    if enable_file_cache:
        cache_flag = pick_tcpreplay_cache_flag()
        if cache_flag:
            cmd.append(cache_flag)

    cmd.append(pcap_path)

    print("[send]", " ".join(cmd))

    if dry_run:
        return

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"tcpreplay failed (rc={proc.returncode}).\n"
            f"CMD: {' '.join(cmd)}\n"
            f"Output:\n{proc.stdout}"
        )


def prepare_aux_pcap(
    sources: Sources,
    out_path: str,
    total_packets: int,
    chunk_size: int,
    prob_mal: float,
    seed: int | None,
) -> None:
    """Crea un PCAP auxiliar con total_packets paquetes, eligiendo chunks al azar."""

    try:
        from scapy.all import PcapReader, PcapWriter  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "No puedo importar scapy. Ojo: si ejecutas con sudo, instala scapy en ese Python.\n"
            "Ejemplo: sudo -H python3 -m pip install scapy\n"
            f"Error original: {e}"
        )

    if seed is not None:
        random.seed(seed)

    def open_reader(path: str):
        return PcapReader(path)

    r_legit = open_reader(sources.legit)
    r_mal = open_reader(sources.mal)

    # sync=False para no flush por paquete (acelera la preparación muchísimo)
    writer = PcapWriter(out_path, append=False, sync=False)

    written = 0

    def get_next_pkt(reader, path: str):
        """Lee siguiente paquete; si EOF, reabre el reader y vuelve a intentar."""
        nonlocal r_legit, r_mal
        try:
            pkt = reader.read_packet()
            if pkt is None:
                raise EOFError
            return pkt, reader
        except Exception:
            try:
                reader.close()
            except Exception:
                pass
            new_reader = open_reader(path)
            pkt = new_reader.read_packet()
            if pkt is None:
                raise RuntimeError(f"El PCAP '{path}' parece vacío o no se puede leer.")
            return pkt, new_reader

    while written < total_packets:
        take_mal = (random.random() < prob_mal)
        n = min(chunk_size, total_packets - written)

        if take_mal:
            reader = r_mal
            path = sources.mal
        else:
            reader = r_legit
            path = sources.legit

        for _ in range(n):
            pkt, new_reader = get_next_pkt(reader, path)
            writer.write(pkt)
            reader = new_reader
            written += 1

        if take_mal:
            r_mal = reader
        else:
            r_legit = reader

    try:
        r_legit.close()
    except Exception:
        pass
    try:
        r_mal.close()
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass


def mktemp_pcap_path() -> str:
    """Crea un path temporal. Preferimos /dev/shm si existe (tmpfs)."""
    base_dir = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
    if base_dir:
        fd, path = tempfile.mkstemp(prefix="aux_mix_", suffix=".pcap", dir=base_dir)
    else:
        fd, path = tempfile.mkstemp(prefix="aux_mix_", suffix=".pcap")
    os.close(fd)
    return path


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Preparación + envío: crea un PCAP auxiliar y lo reenvía a PPS objetivo con tcpreplay (una sola ejecución)."
    )
    ap.add_argument("--legit", required=True, help="Ruta al PCAP legítimo")
    ap.add_argument("--mal", required=True, help="Ruta al PCAP malicioso")
    ap.add_argument("--iface", required=True, help="Interfaz de salida")
    ap.add_argument("--pps", type=float, required=True, help="PPS objetivo")
    ap.add_argument("--duration", type=float, required=True, help="Duración total en segundos")
    ap.add_argument("--prob-mal", type=float, default=0.5, help="Probabilidad de escoger chunk malicioso [0..1]")
    ap.add_argument("--seed", type=int, default=None, help="Semilla aleatoria")

    ap.add_argument("--chunk", type=int, default=100, help="Tamaño de chunk (paquetes)")
    ap.add_argument("--margin", type=float, default=0.20, help="Margen extra al preparar el PCAP (0.20 = +20%%)")

    ap.add_argument("--stats", type=int, default=0, help="Intervalo de stats de tcpreplay en segundos (0 desactiva)")
    ap.add_argument("--no-file-cache", action="store_true", help="Desactivar cache en RAM de tcpreplay")
    ap.add_argument("--dry-run", action="store_true", help="Imprime el comando tcpreplay sin ejecutarlo")

    args = ap.parse_args()

    if not (0.0 <= args.prob_mal <= 1.0):
        raise SystemExit("--prob-mal debe estar entre 0 y 1")
    if args.pps <= 0 or args.duration <= 0:
        raise SystemExit("--pps y --duration deben ser > 0")
    if args.chunk <= 0:
        raise SystemExit("--chunk debe ser > 0")
    if args.margin < 0:
        raise SystemExit("--margin debe ser >= 0")

    pps_int = int(round(args.pps))
    packets_exact = int(round(pps_int * args.duration))
    packets_prepare = int(math.ceil(packets_exact * (1.0 + args.margin)))

    sources = Sources(legit=args.legit, mal=args.mal)

    tmp_path = mktemp_pcap_path()
    try:
        print("=== script_reenvio_v4 settings ===")
        print(f"iface={args.iface}")
        print(f"pps_target={pps_int}")
        print(f"duration={args.duration}s")
        print(f"packets_exact={packets_exact}")
        print(f"packets_prepare={packets_prepare} (+{args.margin*100:.0f}%)")
        print(f"chunk_size={args.chunk} prob_mal={args.prob_mal} seed={args.seed}")
        print(f"file_cache={not args.no_file_cache} stats={args.stats}")
        print("==================================")

        print(f"[prep] preparando PCAP auxiliar: {tmp_path}")
        prepare_aux_pcap(
            sources=sources,
            out_path=tmp_path,
            total_packets=packets_prepare,
            chunk_size=args.chunk,
            prob_mal=args.prob_mal,
            seed=args.seed,
        )
        print("[prep] listo.")

        run_tcpreplay_once(
            iface=args.iface,
            pcap_path=tmp_path,
            pps=pps_int,
            packets=packets_exact,
            duration_s=args.duration,
            stats_interval=args.stats,
            enable_file_cache=(not args.no_file_cache),
            dry_run=args.dry_run,
        )

        print("=== done ===")
        print(f"sent_packets_target={packets_exact}")
        print("============")

    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
                print(f"[cleanup] borrado PCAP auxiliar: {tmp_path}")
            except Exception:
                print(f"[cleanup] WARNING: no se pudo borrar: {tmp_path}")


if __name__ == "__main__":
    main()
