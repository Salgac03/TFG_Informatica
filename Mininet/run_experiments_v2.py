#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_experiments_v2.py

VERSIÓN v2
ÚNICO CAMBIO respecto a la versión anterior:
- En la FASE 3 se sustituye el generador antiguo (trafico_eth_v3.py)
  por el nuevo script_reenvio.py
- NO se toca nada más: CSV, XDP, sleeps, lógica, métricas, TODO igual
"""

import argparse
import csv
import json
import os
import re
import shlex
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

from redarbolrw1 import SimpleTopo

# ======================================================
# CONFIG FIJA
# ======================================================

PPS_STEPS_DEFAULT = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]

# iperf
IPERF_PAYLOAD_LEN = 1400
IPERF_SERVER_PORT = 5201

# tcpreplay
TCPREPLAY_DURATION_DEFAULT = 10

# generator (FASE 3)
GEN_DURATION_DEFAULT = 10.0
GEN_SEED = 12345
GEN_SCRIPT_REL_PATH = "Mininet/script_reenvio.py"

# sleeps
SLEEP_BETWEEN_RUNS_DEFAULT = 2.0
SLEEP_BETWEEN_BLOCKS_DEFAULT = 6.0
SLEEP_BETWEEN_EXPERIMENTS_DEFAULT = 8.0

# XDP
XDP_USR_REL_PATH = "XDP/arbol_prueba/xdp_usr"

# ======================================================
# CSV layout común
# ======================================================

CSV_COMMON = [
    "timestamp",
    "xdp",
    "label",
    "pps_target",
    "pps_measured",
    "packets_total",
    "lost_packets",
    "lost_percent",
    "paquetes_filtrados",
    "paquetes_perdidos_reales",
    "lost_real_percent",
]


def compute_real_losses(packets_total: int, lost_packets: int, filtered: int):
    expected = int(packets_total) + int(lost_packets)
    real_lost = int(lost_packets) - int(filtered)
    if real_lost < 0:
        real_lost = 0
    real_percent = (real_lost / expected * 100.0) if expected > 0 else 0.0
    return real_lost, real_percent


# ======================================================
# UTILS
# ======================================================


def now_tag():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def must_exist_file(path: str, what: str):
    if not os.path.isfile(path):
        raise SystemExit(f"[FATAL] {what} no existe: {path}")


def run_cmd(host, cmd: str) -> str:
    return host.cmd(cmd)


def start_bg(host, cmd: str, pidfile: str, logfile: str):
    host.cmd(f"{cmd} > {shlex.quote(logfile)} 2>&1 & echo $! > {shlex.quote(pidfile)}")


def stop_bg(host, pidfile: str):
    host.cmd(
        f"test -f {shlex.quote(pidfile)} && kill $(cat {shlex.quote(pidfile)}) >/dev/null 2>&1 || true"
    )


def clear_file(host, path: str):
    host.cmd(f"rm -f {shlex.quote(path)} >/dev/null 2>&1 || true")


def get_last_xdp_drop(hdst, log_path: str) -> int:
    cmd = (
        f"(grep -F 'XDP_STATS drop=' {shlex.quote(log_path)} 2>/dev/null "
        f"| tail -n 1 "
        f"| sed -E 's/.*drop=([0-9]+).*/\\1/')"
    )
    out = hdst.cmd(cmd).strip()
    return int(out) if out.isdigit() else 0


def xdp_drop_delta(drops_now: int, drops_prev: int) -> int:
    if drops_now < drops_prev:
        return drops_now
    return drops_now - drops_prev


def count_pcap_packets(host, pcap_path: str) -> int:
    out = host.cmd(f"tcpdump -n -r {shlex.quote(pcap_path)} 2>/dev/null | wc -l")
    try:
        return int(out.strip())
    except Exception:
        return 0


def pps_to_bitrate_bps(pps: int, payload_bytes: int) -> int:
    return int(pps) * int(payload_bytes) * 8


# ======================================================
# FASE 3: GENERADOR (script_reenvio.py)
# ======================================================


def trafico_eth_sweep(net, results_dir: str, repo_root: str,
                     pcap_legit: str, pcap_malign: str,
                     pps_steps, duration: float,
                     sleep_between_runs: float, sleep_between_blocks: float):

    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name

    base_dir = os.path.join(results_dir, "generator")
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, "trafico_eth_results.csv")
    header = CSV_COMMON

    xdp_pid = os.path.join(base_dir, "xdp_usr_generator.pid")
    xdp_log = os.path.join(base_dir, "xdp_usr_generator.log")

    gen_script = abspath(repo_root, GEN_SCRIPT_REL_PATH)
    print(f"[GEN] usando script={gen_script}")
    must_exist_file(gen_script, "script_reenvio.py")

    def one_run(xdp_label: str, pps: int, drops_prev: int) -> int:
        print(f"[GEN] XDP={xdp_label} PPS={pps}")
        tag = f"{xdp_label}_pps{pps}_{now_tag()}"

        rx_pcap = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
        tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
        tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
        gen_log = os.path.join(logs_dir, f"gen_{tag}.log")

        start_bg(
            hdst,
            f"timeout {duration} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(rx_pcap)}",
            tcpdump_pid, tcpdump_log
        )
        time.sleep(0.6)

        import sys
        cmd = (
            f"{shlex.quote(sys.executable)} {shlex.quote(gen_script)} "
            f"--legit {shlex.quote(pcap_legit)} "
            f"--mal {shlex.quote(pcap_malign)} "
            f"--iface {shlex.quote(tx_iface)} "
            f"--pps {int(pps)} "
            f"--duration {duration} "
            f"--seed {GEN_SEED}"
        )

        run_cmd(hsrc, f"{cmd} 2>&1 | tee {shlex.quote(gen_log)}")
        time.sleep(1.0)

        stop_bg(hdst, tcpdump_pid)

        rx_pkts = count_pcap_packets(hdst, rx_pcap)
        pps_measured = (rx_pkts / duration) if duration > 0 else 0.0
        expected = int(round(duration * pps))
        lost = max(0, expected - rx_pkts)
        loss_percent = (lost / expected * 100.0) if expected > 0 else 0.0

        drops_iter = 0
        if xdp_label == "on":
            time.sleep(1.1)
            drops_now = get_last_xdp_drop(hdst, xdp_log)
            drops_iter = xdp_drop_delta(drops_now, drops_prev)
            drops_prev = drops_now

        real_lost, real_percent = compute_real_losses(rx_pkts, lost, drops_iter)

        row = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "xdp": xdp_label,
            "label": "generator",
            "pps_target": pps,
            "pps_measured": f"{pps_measured:.2f}",
            "packets_total": int(rx_pkts),
            "lost_packets": int(lost),
            "lost_percent": f"{loss_percent:.4f}",
            "paquetes_filtrados": int(drops_iter),
            "paquetes_perdidos_reales": int(real_lost),
            "lost_real_percent": f"{real_percent:.4f}",
        }

        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=header)
            if write_header:
                w.writeheader()
            w.writerow(row)

        return drops_prev

    print("[GEN] sin XDP")
    drops_prev = 0
    for pps in pps_steps:
        drops_prev = one_run("off", pps, drops_prev)
        time.sleep(sleep_between_runs)

    time.sleep(sleep_between_blocks)

    print("[GEN] con XDP (delta por PPS, sin reinicios)")
    clear_file(hdst, xdp_log)
    start_bg(hdst, f"{abspath(repo_root, XDP_USR_REL_PATH)} {rx_iface}", xdp_pid, xdp_log)
    time.sleep(0.8)
    drops_prev = get_last_xdp_drop(hdst, xdp_log)
    try:
        for pps in pps_steps:
            drops_prev = one_run("on", pps, drops_prev)
            time.sleep(sleep_between_runs)
    finally:
        stop_bg(hdst, xdp_pid)


# ======================================================
# MAIN
# ======================================================


def main():
    if os.geteuid() != 0:
        raise SystemExit("Este script debe ejecutarse como root (sudo).")

    ap = argparse.ArgumentParser(description="Suite Mininet v2 (FASE 3 con script_reenvio.py)")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("-l", "--legit", dest="pcap_legit", required=True)
    ap.add_argument("-m", "--malign", dest="pcap_malign", required=True)
    ap.add_argument("--skip-generator", action="store_true")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    repo_root = args.repo_root
    pcap_legit = abspath(repo_root, args.pcap_legit)
    pcap_malign = abspath(repo_root, args.pcap_malign)

    must_exist_file(pcap_legit, "PCAP legit")
    must_exist_file(pcap_malign, "PCAP malign")

    pps_steps = PPS_STEPS_DEFAULT
    gen_duration = GEN_DURATION_DEFAULT
    sleep_runs = SLEEP_BETWEEN_RUNS_DEFAULT
    sleep_blocks = SLEEP_BETWEEN_BLOCKS_DEFAULT

    if args.quick:
        pps_steps = [64, 128]
        gen_duration = 3.0
        sleep_runs = 0.5
        sleep_blocks = 1.0

    suite_dir = f"/tmp/exp_suite_{now_tag()}"
    os.makedirs(suite_dir, exist_ok=True)

    net = Mininet(topo=SimpleTopo(), controller=None,
                  switch=OVSSwitch, link=TCLink, autoSetMacs=False)
    net.start()
    try:
        if not args.skip_generator:
            trafico_eth_sweep(net, suite_dir, repo_root,
                             pcap_legit, pcap_malign,
                             pps_steps, gen_duration,
                             sleep_runs, sleep_blocks)
    finally:
        net.stop()
        print(f"[INFO] Fin. Resultados en {suite_dir}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
