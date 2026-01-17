#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_experiments_suite_v12_xdpdrop_delta.py

Basado en el script que me pasaste (suite v12 con XDP_DROP por delta, SIN reinicios
de xdp_usr) y con cambios *solo* de CSV:

CSV (los 3 tipos) arranca con este orden fijo:
  1) timestamp
  2) xdp
  3) label
  4) pps_target
  5) pps_measured
  6) packets_total
  7) lost_packets
  8) lost_percent
  9) paquetes_filtrados
 10) paquetes_perdidos_reales = max(0, lost_packets - paquetes_filtrados)
 11) lost_real_percent = paquetes_perdidos_reales / expected * 100

Luego cada prueba añade sus columnas extra (iperf: bps_measured; generator: tx_*).

IMPORTANTE: no se toca la lógica de "paquetes_filtrados" (delta por iteración).
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

# trafico_eth (tu generador)
GEN_DURATION_DEFAULT = 10.0
GEN_BURST_MS = 200
GEN_P_MAL = 0.5
GEN_BATCH = 64
GEN_SEED = 12345

# sleeps
SLEEP_BETWEEN_RUNS_DEFAULT = 2.0
SLEEP_BETWEEN_BLOCKS_DEFAULT = 6.0
SLEEP_BETWEEN_EXPERIMENTS_DEFAULT = 8.0

# XDP
XDP_USR_REL_PATH = "XDP/arbol_prueba/xdp_usr"

# generador
GEN_SCRIPT_REL_PATH = "Mininet/script_reenvio_v3.py"
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
    """Calcula pérdidas reales y su %.

    expected = packets_total + lost_packets
    real_lost = max(0, lost_packets - filtered)
    real_percent = real_lost / expected * 100
    """
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
    """Devuelve el último contador XDP_DROP del log de xdp_usr (o 0 si no existe)."""
    cmd = (
        f"(grep -F 'XDP_STATS drop=' {shlex.quote(log_path)} 2>/dev/null "
        f"| tail -n 1 "
        f"| sed -E 's/.*drop=([0-9]+).*/\\1/'"  # preferido
        f") || "
        f"(grep -F 'Total de paquetes descartados (XDP_DROP):' {shlex.quote(log_path)} 2>/dev/null "
        f"| tail -n 1 "
        f"| sed -E 's/.*: *([0-9]+).*/\\1/')"
    )
    out = hdst.cmd(cmd).strip()
    return int(out) if out.isdigit() else 0


def xdp_drop_delta(drops_now: int, drops_prev: int) -> int:
    """Delta robusto por iteración (si el contador se resetea, no devolvemos negativos)."""
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


def start_xdp(hdst, repo_root: str, iface: str, pid_path: str, log_path: str):
    xdp_bin = os.path.join(repo_root, XDP_USR_REL_PATH)
    xdp_dir = os.path.dirname(xdp_bin)
    xdp_name = os.path.basename(xdp_bin)

    run_cmd(hdst, f"chmod +x {shlex.quote(xdp_bin)}")

    runline = (
        "bash -lc "
        + shlex.quote(
            f"cd {shlex.quote(xdp_dir)} && "
            f"echo '[XDP] start ts='$(date -Iseconds)' cwd='$(pwd)' iface={shlex.quote(iface)} bin={shlex.quote(xdp_bin)}' ; "
            f"echo '[XDP] build: make clean && make' ; "
            f"make -C {shlex.quote(xdp_dir)} clean 2>&1 | sed 's/^/[XDP][CLEAN] /' ; "
            f"make -C {shlex.quote(xdp_dir)} 2>&1 | sed 's/^/[XDP][MAKE] /' ; "
            f"chmod +x {shlex.quote('./' + xdp_name)} ; "
            f"ldd {shlex.quote('./' + xdp_name)} | grep -i libbpf | sed 's/^/[XDP][LDD] /' || true ; "
            f"ls -l xdp_kern.o 2>&1 | sed 's/^/[XDP] /' ; "
            f"exec {shlex.quote('./' + xdp_name)} {shlex.quote(iface)}"
        )
    )

    start_bg(hdst, runline, pid_path, log_path)


def preflight(net, suite_dir: str):
    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name
    hdst_ip = hdst.IP()
    print(f"[PRE] hsrc.iface={tx_iface} hdst.iface={rx_iface} hdst.ip={hdst_ip}")
    ping_out = hsrc.cmd(f"ping -c 1 -W 1 {hdst_ip}")
    print("[PRE] ping:\n" + ping_out)


# ======================================================
# IPERF
# ======================================================


def parse_iperf_json(out: str, duration: int):
    j = json.loads(out)
    end = j.get("end", {})
    s = end.get("sum", {}) or end.get("sum_received", {}) or {}

    packets = int(s.get("packets", 0))
    lost_packets = int(s.get("lost_packets", 0))
    lost_percent = float(s.get("lost_percent", 0.0))
    bps = float(s.get("bits_per_second", 0.0))
    measured_pps = packets / duration if duration > 0 else 0.0
    return packets, lost_packets, lost_percent, bps, measured_pps


def iperf_sweep(net, results_dir: str, repo_root: str, pps_steps, duration: int, sleep_between_runs: float, sleep_between_blocks: float):
    os.makedirs(results_dir, exist_ok=True)
    raw_dir = os.path.join(results_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    hsrc, hdst = net["hsrc"], net["hdst"]
    hdst_ip = hdst.IP()
    rx_iface = hdst.defaultIntf().name

    csv_path = os.path.join(results_dir, "iperf_results.csv")
    header = CSV_COMMON + ["bps_measured"]

    xdp_pid = os.path.join(results_dir, "xdp_usr_iperf.pid")
    xdp_log = os.path.join(results_dir, "xdp_usr_iperf.log")

    def one_run(xdp_label: str, pps: int, drops_prev: int) -> int:
        print(f"[IPERF] XDP={xdp_label} PPS={pps}")
        bitrate = pps_to_bitrate_bps(pps, IPERF_PAYLOAD_LEN)

        tag = f"{xdp_label}_pps{pps}_{now_tag()}"
        srv_log = os.path.join(raw_dir, f"iperf_srv_{tag}.log")
        srv_pid = os.path.join(raw_dir, f"iperf_srv_{tag}.pid")
        cli_raw = os.path.join(raw_dir, f"iperf_cli_{tag}.txt")

        start_bg(hdst, f"iperf3 -s -p {IPERF_SERVER_PORT}", srv_pid, srv_log)
        time.sleep(0.3)

        cmd = (
            f"iperf3 -c {hdst_ip} -p {IPERF_SERVER_PORT} "
            f"-u -t {duration} -l {IPERF_PAYLOAD_LEN} -b {bitrate} -J"
        )
        out = run_cmd(hsrc, cmd)
        with open(cli_raw, "w") as f:
            f.write(out)

        stop_bg(hdst, srv_pid)

        try:
            packets, lost_packets, lost_percent, bps, pps_measured = parse_iperf_json(out, duration)
        except Exception:
            packets = lost_packets = 0
            lost_percent = 0.0
            bps = pps_measured = 0.0

        drops_iter = 0
        if xdp_label == "on":
            time.sleep(1.1)
            drops_now = get_last_xdp_drop(hdst, xdp_log)
            drops_iter = xdp_drop_delta(drops_now, drops_prev)
            drops_prev = drops_now

        real_lost, real_percent = compute_real_losses(packets, lost_packets, drops_iter)

        row = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "xdp": xdp_label,
            "label": "iperf",
            "pps_target": pps,
            "pps_measured": f"{pps_measured:.2f}",
            "packets_total": int(packets),
            "lost_packets": int(lost_packets),
            "lost_percent": f"{float(lost_percent):.4f}",
            "paquetes_filtrados": int(drops_iter),
            "paquetes_perdidos_reales": int(real_lost),
            "lost_real_percent": f"{real_percent:.4f}",
            "bps_measured": f"{bps:.2f}",
        }

        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=header)
            if write_header:
                w.writeheader()
            w.writerow(row)

        return drops_prev

    # --- OFF ---
    print("[IPERF] sin XDP")
    drops_prev = 0
    for pps in pps_steps:
        drops_prev = one_run("off", pps, drops_prev)
        time.sleep(sleep_between_runs)

    time.sleep(sleep_between_blocks)

    # --- ON (xdp_usr vivo durante todo el bloque) ---
    print("[IPERF] con XDP (delta por PPS, sin reinicios)")
    clear_file(hdst, xdp_log)
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)
    time.sleep(0.8)
    drops_prev = get_last_xdp_drop(hdst, xdp_log)
    try:
        for pps in pps_steps:
            drops_prev = one_run("on", pps, drops_prev)
            time.sleep(sleep_between_runs)
    finally:
        stop_bg(hdst, xdp_pid)


# ======================================================
# TCPREPLAY
# ======================================================


def tcpreplay_sweep(net, results_dir: str, repo_root: str, pcap_path: str, label: str,
                   pps_steps, duration: int, sleep_between_runs: float, sleep_between_blocks: float):
    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name

    base_dir = os.path.join(results_dir, label)
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, f"tcpreplay_{label}_results.csv")
    header = CSV_COMMON

    xdp_pid = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.pid")
    xdp_log = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.log")

    must_exist_file(pcap_path, f"PCAP {label} (mininet prewritten)")
    print(f"[TCP] {label} usando PCAP={pcap_path}")

    def one_run(xdp_label: str, pps: int, drops_prev: int) -> int:
        print(f"[TCP] {label} XDP={xdp_label} PPS={pps}")
        tag = f"{label}_{xdp_label}_pps{pps}_{now_tag()}"

        rx_pcap = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
        tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
        tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
        tcpreplay_log = os.path.join(logs_dir, f"tcpreplay_{tag}.log")
        start_bg(
            hdst,
            f"timeout {duration} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(rx_pcap)}",
            tcpdump_pid, tcpdump_log
        )
        time.sleep(0.6)

        limit_pkts = int(round(duration * pps))
        play_cmd = (
            f"timeout {int(duration) + 3} "
            f"tcpreplay --intf1={shlex.quote(tx_iface)} --pps={int(pps)} --limit={limit_pkts} "
            f"{shlex.quote(pcap_path)}"
        )
        run_cmd(hsrc, f"{play_cmd} > {shlex.quote(tcpreplay_log)} 2>&1")

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
            "label": label,
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

    # --- OFF ---
    print(f"[TCP] {label} sin XDP")
    drops_prev = 0
    for pps in pps_steps:
        drops_prev = one_run("off", pps, drops_prev)
        time.sleep(sleep_between_runs)

    time.sleep(sleep_between_blocks)

    # --- ON ---
    print(f"[TCP] {label} con XDP (delta por PPS, sin reinicios)")
    clear_file(hdst, xdp_log)
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)
    time.sleep(0.8)
    drops_prev = get_last_xdp_drop(hdst, xdp_log)
    try:
        for pps in pps_steps:
            drops_prev = one_run("on", pps, drops_prev)
            time.sleep(sleep_between_runs)
    finally:
        stop_bg(hdst, xdp_pid)


# ======================================================
# TRAFICO_ETH
# ======================================================


GEN_BURST_RE = re.compile(
    r"\[burst\s+\d+\]\s+type=(?P<typ>MAL|LEGIT)\s+pkts=(?P<pkts>\d+)"
)
GEN_DONE_RE = re.compile(r"elapsed=(?P<elapsed>[0-9.]+)s")


def parse_gen_stdout(out: str, default_elapsed: float):
    """Parsea stdout del generador (script_reenvio_*).

    Soporta dos formatos:
      1) Por ráfagas (antiguo):
         [burst N] type=MAL/LEGIT pkts=...
         ...
         elapsed=...s

      2) Por PCAP auxiliar (nuevo):
         sent_packets_target=NNN
         (opcionalmente) sent_packets=NNN

    Devuelve: tx_total/tx_legit/tx_mal/elapsed
    """
    legit = mal = total = 0

    # Formato 1: ráfagas
    for m in GEN_BURST_RE.finditer(out):
        pkts = int(m.group("pkts"))
        total += pkts
        if m.group("typ") == "MAL":
            mal += pkts
        else:
            legit += pkts

    # Formato 2: objetivo explícito
    if total == 0:
        import re
        m_target = re.search(r"sent_packets_target=(\d+)", out)
        if m_target:
            total = int(m_target.group(1))
            # En este modo no distinguimos legit/mal en TX (a menos que el generador lo imprima)
            legit = 0
            mal = 0

    m2 = GEN_DONE_RE.search(out)
    elapsed = float(m2.group("elapsed")) if m2 else float(default_elapsed)

    return {"tx_total": total, "tx_legit": legit, "tx_mal": mal, "elapsed": elapsed}




def trafico_eth_sweep(net, results_dir: str, repo_root: str, pcap_legit: str, pcap_malign: str,
                     pps_steps, duration: float, sleep_between_runs: float, sleep_between_blocks: float):
    hsrc, hdst = net["hsrc"], net["hdst"]
    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name
    hdst_ip = hdst.IP()
    src_mac = hsrc.MAC()
    dst_mac = hdst.MAC()

    base_dir = os.path.join(results_dir, "trafico_eth")
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, "trafico_eth_results.csv")
    header = CSV_COMMON + ["tx_packets_total", "tx_legit_packets", "tx_mal_packets"]

    xdp_pid = os.path.join(base_dir, "xdp_usr_trafico_eth.pid")
    xdp_log = os.path.join(base_dir, "xdp_usr_trafico_eth.log")

    gen_script = abspath(repo_root, GEN_SCRIPT_REL_PATH)
    print(f"[GEN] usando script={gen_script}")
    must_exist_file(gen_script, "trafico_eth.py")

    must_exist_file(pcap_legit, "PCAP legit para generador")
    must_exist_file(pcap_malign, "PCAP malign para generador")

    def one_run(xdp_label: str, pps: int, drops_prev: int) -> int:
        print(f"[GEN] XDP={xdp_label} PPS={pps}")
        tag = f"{xdp_label}_pps{pps}_{now_tag()}"

        rx_pcap = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
        tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
        tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
        gen_log = os.path.join(logs_dir, f"gen_{tag}.log")

        start_bg(
            hdst,
            f"tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(rx_pcap)} \"ether src {src_mac} and ether dst {dst_mac}\"",
            tcpdump_pid, tcpdump_log
        )
        time.sleep(0.6)

        import sys
        cmd = (
            f"{shlex.quote(sys.executable)} {shlex.quote(gen_script)} "
            f"--legit {shlex.quote(pcap_legit)} "
            f"--mal {shlex.quote(pcap_malign)} "
            f"--iface {shlex.quote(tx_iface)} "
            f"--pps {float(pps)} "
            f"--duration {float(duration)} "
            f"--prob-mal {GEN_P_MAL} "
            f"--seed {GEN_SEED}"
        )
        out = run_cmd(hsrc, f"{cmd} 2>&1 | tee {shlex.quote(gen_log)}")
        time.sleep(1.0)

        tx = parse_gen_stdout(out, duration)
        tx_total = tx["tx_total"]

        stop_bg(hdst, tcpdump_pid)

        rx_pkts = count_pcap_packets(hdst, rx_pcap)
        pps_measured = (rx_pkts / float(duration)) if duration > 0 else 0.0
        lost = max(0, tx_total - rx_pkts)
        loss_percent = (lost / tx_total * 100.0) if tx_total > 0 else 0.0

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
            "label": "trafico_eth",
            "pps_target": pps,
            "pps_measured": f"{pps_measured:.2f}",
            "packets_total": int(rx_pkts),
            "lost_packets": int(lost),
            "lost_percent": f"{loss_percent:.4f}",
            "paquetes_filtrados": int(drops_iter),
            "paquetes_perdidos_reales": int(real_lost),
            "lost_real_percent": f"{real_percent:.4f}",
            "tx_packets_total": int(tx_total),
            "tx_legit_packets": int(tx["tx_legit"]),
            "tx_mal_packets": int(tx["tx_mal"]),
        }

        write_header = not os.path.exists(csv_path)
        with open(csv_path, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=header)
            if write_header:
                w.writeheader()
            w.writerow(row)

        return drops_prev

    # --- OFF ---
    print("[GEN] sin XDP")
    drops_prev = 0
    for pps in pps_steps:
        drops_prev = one_run("off", pps, drops_prev)
        time.sleep(sleep_between_runs)

    time.sleep(sleep_between_blocks)

    # --- ON ---
    print("[GEN] con XDP (delta por PPS, sin reinicios)")
    clear_file(hdst, xdp_log)
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)
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

    ap = argparse.ArgumentParser(description="Suite Mininet v12 (XDP_DROP por delta, CSV reordenado + pérdidas reales)")
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("-l", "--legit", dest="pcap_legit", required=True,
                    help="PCAP legit ya prewritten para Mininet (recomendado)")
    ap.add_argument("-m", "--malign", dest="pcap_malign", required=True,
                    help="PCAP malign ya prewritten para Mininet (recomendado)")
    ap.add_argument("--skip-iperf", action="store_true")
    ap.add_argument("--skip-tcpreplay", action="store_true")
    ap.add_argument("--skip-generator", action="store_true")
    ap.add_argument("--quick", action="store_true", help="Reduce duraciones y sleeps para depurar rápido")
    args = ap.parse_args()

    repo_root = args.repo_root

    pcap_legit = abspath(repo_root, args.pcap_legit)
    pcap_malign = abspath(repo_root, args.pcap_malign)

    must_exist_file(pcap_legit, "PCAP legit")
    must_exist_file(pcap_malign, "PCAP malign")

    pps_steps = PPS_STEPS_DEFAULT
    iperf_duration = 10
    tcpreplay_duration = TCPREPLAY_DURATION_DEFAULT
    gen_duration = GEN_DURATION_DEFAULT
    sleep_runs = SLEEP_BETWEEN_RUNS_DEFAULT
    sleep_blocks = SLEEP_BETWEEN_BLOCKS_DEFAULT
    sleep_exp = SLEEP_BETWEEN_EXPERIMENTS_DEFAULT

    if args.quick:
        pps_steps = [64, 128]
        iperf_duration = 3
        tcpreplay_duration = 3
        gen_duration = 3.0
        sleep_runs = 0.5
        sleep_blocks = 1.0
        sleep_exp = 1.0

    suite_dir = f"/tmp/exp_suite_{now_tag()}"
    os.makedirs(suite_dir, exist_ok=True)
    iperf_dir = os.path.join(suite_dir, "iperf")
    tcpr_dir = os.path.join(suite_dir, "tcpreplay")
    gen_dir = os.path.join(suite_dir, "generator")
    os.makedirs(iperf_dir, exist_ok=True)
    os.makedirs(tcpr_dir, exist_ok=True)
    os.makedirs(gen_dir, exist_ok=True)

    net = Mininet(topo=SimpleTopo(), controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)
    net.start()
    try:
        print(f"[INFO] Mininet iniciado. Resultados en {suite_dir}")
        preflight(net, suite_dir)

        if not args.skip_iperf:
            print("[INFO] ====== FASE 1: IPERF ======")
            iperf_sweep(net, iperf_dir, repo_root, pps_steps, iperf_duration, sleep_runs, sleep_blocks)
            time.sleep(sleep_exp)

        if not args.skip_tcpreplay:
            print("[INFO] ====== FASE 2: TCPREPLAY (legit/malign) ======")
            tcpreplay_sweep(net, tcpr_dir, repo_root, pcap_legit, "legit", pps_steps, tcpreplay_duration, sleep_runs, sleep_blocks)
            time.sleep(sleep_exp)
            tcpreplay_sweep(net, tcpr_dir, repo_root, pcap_malign, "malign", pps_steps, tcpreplay_duration, sleep_runs, sleep_blocks)
            time.sleep(sleep_exp)

        if not args.skip_generator:
            print("[INFO] ====== FASE 3: TRAFICO_ETH ======")
            trafico_eth_sweep(net, gen_dir, repo_root, pcap_legit, pcap_malign, pps_steps, gen_duration, sleep_runs, sleep_blocks)

    finally:
        net.stop()
        print(f"[INFO] Fin. Resultados en {suite_dir}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
