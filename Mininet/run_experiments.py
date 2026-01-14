#!/usr/bin/env python3
# v8: Suite completa (iperf + tcpreplay legit/malign + trafico_eth) con fix definitivo para tcpreplay en tu entorno:
#     - tcpreplay NO usa --fixcsum (tu versión falla con "illegal option -- fixcsum")
#     - checksums/MACs se ajustan con tcprewrite (--enet-smac/--enet-dmac --fixcsum)
#     - rutas PCAP se resuelven y VALIDAN (fatal si no existen)
#     - ifaces/IP/MACs detectadas desde Mininet (no hardcode)
#
# Flags:
#   --repo-root (obligatorio)
#   -l / --legit   (PCAP legítimo)
#   -m / --malign  (PCAP maligno)
#   --skip-iperf / --skip-tcpreplay / --skip-generator (opcionales)
#
# Salida: /tmp/exp_suite_<tag>/
#
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
# CONFIGURACIÓN EXPERIMENTAL FIJA
# ======================================================

# PPS steps (modo "normal" pero razonable)
PPS_STEPS = [64, 128, 256, 512, 1000, 2000]

# iperf
IPERF_DURATION = 10
IPERF_PAYLOAD_LEN = 1400
IPERF_SERVER_PORT = 5201

# tcpreplay
TCPREPLAY_DURATION = 10

# tu generador (trafico_eth.py)
GEN_DURATION = 10.0
GEN_BURST_MS = 200
GEN_P_MAL = 0.5
GEN_BATCH = 64
GEN_SEED = 12345

# sleeps
SLEEP_BETWEEN_RUNS = 2.0
SLEEP_BETWEEN_BLOCKS = 8.0
SLEEP_BETWEEN_EXPERIMENTS = 10.0

# XDP
XDP_USR_REL_PATH = "XDP/arbol_prueba/xdp_usr"

# Ruta al script del generador (relativa al repo-root)
GEN_SCRIPT_REL_PATH = "trafico_eth.py"


# ======================================================
# UTILIDADES
# ======================================================

def now_tag():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(host, path):
    host.cmd(f"mkdir -p {shlex.quote(path)}")


def run_cmd(host, cmd):
    return host.cmd(cmd)


def start_bg(host, cmd, pidfile, logfile):
    host.cmd(
        f"{cmd} > {shlex.quote(logfile)} 2>&1 & "
        f"echo $! > {shlex.quote(pidfile)}"
    )


def stop_bg(host, pidfile):
    host.cmd(f"kill $(cat {shlex.quote(pidfile)}) >/dev/null 2>&1 || true")


def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def must_exist_file(path: str, what: str):
    if not path:
        return
    if not os.path.isfile(path):
        raise SystemExit(f"[FATAL] {what} no existe: {path}")


def count_pcap_packets(host, pcap_path: str) -> int:
    out = host.cmd(f"tcpdump -n -r {shlex.quote(pcap_path)} 2>/dev/null | wc -l")
    try:
        return int(out.strip())
    except Exception:
        return 0


def start_xdp(hdst, repo_root, xdp_iface, pid_path, log_path):
    xdp_bin = os.path.join(repo_root, XDP_USR_REL_PATH)
    run_cmd(hdst, f"chmod +x {shlex.quote(xdp_bin)}")
    start_bg(hdst, f"{shlex.quote(xdp_bin)} {shlex.quote(xdp_iface)}", pid_path, log_path)


def preflight(net, suite_dir: str):
    """Diagnóstico rápido: IP/iface/MAC + ping"""
    hsrc, hdst = net["hsrc"], net["hdst"]

    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name
    hdst_ip = hdst.IP()
    hsrc_mac = hsrc.MAC()
    hdst_mac = hdst.MAC()

    diag_dir = os.path.join(suite_dir, "diagnostics")
    os.makedirs(diag_dir, exist_ok=True)

    print(f"[PRE] hsrc.iface={tx_iface} hdst.iface={rx_iface} hdst.ip={hdst_ip}")
    print(f"[PRE] hsrc.mac={hsrc_mac} hdst.mac={hdst_mac}")

    with open(os.path.join(diag_dir, "hsrc_ip_addr.txt"), "w") as f:
        f.write(hsrc.cmd("ip -br addr"))
    with open(os.path.join(diag_dir, "hdst_ip_addr.txt"), "w") as f:
        f.write(hdst.cmd("ip -br addr"))

    ping_out = hsrc.cmd(f"ping -c 1 -W 1 {hdst_ip}")
    print("[PRE] ping:")
    print(ping_out)
    with open(os.path.join(diag_dir, "ping.txt"), "w") as f:
        f.write(ping_out)

    if ("1 received" not in ping_out) and ("1 packets received" not in ping_out):
        print("[PRE][WARN] El ping NO llega. Iperf/tcpreplay/generador pueden fallar por conectividad.")
    else:
        print("[PRE] ping OK")


# ======================================================
# IPERF
# ======================================================

def pps_to_bitrate_bps(pps, payload_bytes):
    return pps * payload_bytes * 8


def parse_iperf_json(j, duration):
    end = j.get("end", {})
    s = end.get("sum", {}) or end.get("sum_received", {}) or {}

    packets = int(s.get("packets", 0))
    lost_packets = int(s.get("lost_packets", 0))
    lost_percent = float(s.get("lost_percent", 0.0))
    bps = float(s.get("bits_per_second", 0.0))
    measured_pps = packets / duration if duration > 0 else 0.0

    return packets, lost_packets, lost_percent, bps, measured_pps


def iperf_sweep(net, results_dir, repo_root):
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

    hdst_ip = hdst.IP()
    rx_iface = hdst.defaultIntf().name

    csv_path = os.path.join(results_dir, "iperf_results.csv")
    raw_dir = os.path.join(results_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    header = [
        "timestamp",
        "xdp",
        "pps_target",
        "pps_measured",
        "bps_measured",
        "lost_percent",
        "lost_packets",
        "packets_total",
        "note",
    ]

    def run_block(xdp_label):
        for pps in PPS_STEPS:
            print(f"[INFO] IPERF | XDP={xdp_label} | PPS objetivo = {pps}")
            bitrate = pps_to_bitrate_bps(pps, IPERF_PAYLOAD_LEN)

            tag = f"{xdp_label}_pps{pps}_{now_tag()}"
            srv_log = os.path.join(raw_dir, f"iperf_srv_{tag}.log")
            srv_pid = os.path.join(raw_dir, f"iperf_srv_{tag}.pid")

            cli_raw = os.path.join(raw_dir, f"iperf_cli_{tag}.txt")
            cli_json = os.path.join(raw_dir, f"iperf_cli_{tag}.json")

            start_bg(hdst, f"iperf3 -s -p {IPERF_SERVER_PORT}", srv_pid, srv_log)
            time.sleep(0.3)

            cmd = (
                f"iperf3 -c {hdst_ip} "
                f"-p {IPERF_SERVER_PORT} "
                f"-u -t {IPERF_DURATION} "
                f"-l {IPERF_PAYLOAD_LEN} "
                f"-b {bitrate} "
                f"-J"
            )

            out = run_cmd(hsrc, cmd)
            with open(cli_raw, "w") as f:
                f.write(out)

            stop_bg(hdst, srv_pid)

            note = ""
            try:
                j = json.loads(out)
                with open(cli_json, "w") as f:
                    json.dump(j, f, indent=2)
                packets, lost_packets, lost_percent, bps, measured_pps = parse_iperf_json(j, IPERF_DURATION)
            except Exception:
                packets = lost_packets = 0
                lost_percent = 0.0
                bps = measured_pps = 0.0
                note = "iperf_json_parse_failed (ver raw)"

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "pps_target": pps,
                "pps_measured": f"{measured_pps:.2f}",
                "bps_measured": f"{bps:.2f}",
                "lost_percent": f"{lost_percent:.2f}",
                "lost_packets": lost_packets,
                "packets_total": packets,
                "note": note,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(SLEEP_BETWEEN_RUNS)

    print("[INFO] iperf SIN XDP")
    run_block("off")

    time.sleep(SLEEP_BETWEEN_BLOCKS)

    xdp_pid = os.path.join(results_dir, "xdp_usr.pid")
    xdp_log = os.path.join(results_dir, "xdp_usr.log")

    print(f"[INFO] Activando XDP en {rx_iface} (iperf)")
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)

    try:
        print("[INFO] iperf CON XDP")
        run_block("on")
    finally:
        print("[INFO] Desactivando XDP (iperf)")
        stop_bg(hdst, xdp_pid)


# ======================================================
# TCPREPLAY (FIX)
# ======================================================

def tcpreplay_sweep(net, results_dir: str, repo_root: str, pcap_path: str, label: str):
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

    tx_iface = hsrc.defaultIntf().name
    rx_iface = hdst.defaultIntf().name
    smac = hsrc.MAC()
    dmac = hdst.MAC()

    base_dir = os.path.join(results_dir, label)
    pcaps_dir = os.path.join(base_dir, "pcaps")
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(pcaps_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)

    csv_path = os.path.join(base_dir, f"tcpreplay_{label}_results.csv")

    header = [
        "timestamp", "xdp", "label",
        "pps_target", "pps_measured",
        "bps_measured",
        "lost_percent", "lost_packets", "packets_total",
        "note",
    ]

    pcap_in = abspath(repo_root, pcap_path)
    must_exist_file(pcap_in, f"PCAP {label}")
    print(f"[INFO] TCPREPLAY({label}) usando pcap_in={pcap_in}")

    def run_block(xdp_label: str):
        for pps in PPS_STEPS:
            print(f"[INFO] TCPREPLAY({label}) | XDP={xdp_label} | PPS objetivo = {pps}")

            tag = f"{label}_{xdp_label}_pps{pps}_{now_tag()}"
            pcap_out = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
            pcap_rewritten = os.path.join(pcaps_dir, f"tx_{tag}_rewritten.pcap")

            tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
            tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
            tcprewrite_log = os.path.join(logs_dir, f"tcprewrite_{tag}.log")
            tcpreplay_log = os.path.join(logs_dir, f"tcpreplay_{tag}.log")

            # Captura RX
            start_bg(
                hdst,
                f"timeout {TCPREPLAY_DURATION} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(pcap_out)}",
                tcpdump_pid,
                tcpdump_log,
            )
            time.sleep(0.6)

            # Reescritura MACs + fixcsum en tcprewrite
            rewrite_cmd = (
                f"tcprewrite --enet-smac={smac} --enet-dmac={dmac} --fixcsum "
                f"--infile={shlex.quote(pcap_in)} --outfile={shlex.quote(pcap_rewritten)}"
            )
            rewrite_out = run_cmd(hsrc, f"{rewrite_cmd} > {shlex.quote(tcprewrite_log)} 2>&1; echo $?").strip().splitlines()
            rewrite_rc = int(rewrite_out[-1]) if rewrite_out and rewrite_out[-1].isdigit() else 99

            note = ""
            pcap_to_send = pcap_in
            if rewrite_rc == 0 and os.path.isfile(pcap_rewritten):
                pcap_to_send = pcap_rewritten
            else:
                note = f"tcprewrite_rc={rewrite_rc} (ver log)"

            # Replay SIN --fixcsum (tu tcpreplay no lo soporta)
            play_cmd = (
                f"tcpreplay --intf1={shlex.quote(tx_iface)} --pps={int(pps)} "
                f"{shlex.quote(pcap_to_send)}"
            )
            play_out = run_cmd(hsrc, f"{play_cmd} > {shlex.quote(tcpreplay_log)} 2>&1; echo $?").strip().splitlines()
            play_rc = int(play_out[-1]) if play_out and play_out[-1].isdigit() else 99
            if play_rc != 0:
                note = (note + "; " if note else "") + f"tcpreplay_rc={play_rc} (ver log)"

            time.sleep(1.0)
            stop_bg(hdst, tcpdump_pid)

            rx_pkts = count_pcap_packets(hdst, pcap_out)
            pps_measured = (rx_pkts / TCPREPLAY_DURATION) if TCPREPLAY_DURATION > 0 else 0.0

            expected = int(round(TCPREPLAY_DURATION * pps))
            lost = max(0, expected - rx_pkts)
            loss_percent = (lost / expected * 100.0) if expected > 0 else 0.0

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "label": label,
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "bps_measured": "0.00",
                "lost_percent": f"{loss_percent:.2f}",
                "lost_packets": lost,
                "packets_total": rx_pkts,
                "note": note,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(SLEEP_BETWEEN_RUNS)

    print(f"[INFO] tcpreplay({label}) SIN XDP")
    run_block("off")

    time.sleep(SLEEP_BETWEEN_BLOCKS)

    xdp_pid = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.pid")
    xdp_log = os.path.join(base_dir, f"xdp_usr_tcpreplay_{label}.log")

    print(f"[INFO] Activando XDP en {rx_iface} (tcpreplay {label})")
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)

    try:
        print(f"[INFO] tcpreplay({label}) CON XDP")
        run_block("on")
    finally:
        print(f"[INFO] Desactivando XDP (tcpreplay {label})")
        stop_bg(hdst, xdp_pid)


# ======================================================
# TRAFICO_ETH (sin cambios aquí; aún lo depuramos luego)
# ======================================================

GEN_OUT_RE = re.compile(
    r"total=(?P<total>\d+)\s+pps≈(?P<pps>[0-9.]+)\s+legit=(?P<legit>\d+)\s+mal=(?P<mal>\d+).*elapsed=(?P<elapsed>[0-9.]+)s"
)

def parse_gen_stdout(out: str):
    m = GEN_OUT_RE.search(out)
    if not m:
        return {"tx_total": 0, "tx_legit": 0, "tx_mal": 0, "elapsed": float(GEN_DURATION)}
    return {
        "tx_total": int(m.group("total")),
        "tx_legit": int(m.group("legit")),
        "tx_mal": int(m.group("mal")),
        "elapsed": float(m.group("elapsed")),
    }


def trafico_eth_sweep(net, results_dir: str, repo_root: str, pcap_legit: str, pcap_malign: str):
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

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

    header = [
        "timestamp","xdp","label",
        "pps_target","pps_measured","bps_measured",
        "lost_percent","lost_packets","packets_total",
        "tx_packets_total","tx_legit_packets","tx_mal_packets",
        "note",
    ]

    gen_script = abspath(repo_root, GEN_SCRIPT_REL_PATH)
    must_exist_file(gen_script, "trafico_eth.py")
    legit_abs = abspath(repo_root, pcap_legit)
    mal_abs = abspath(repo_root, pcap_malign)
    must_exist_file(legit_abs, "PCAP legit para generador")
    must_exist_file(mal_abs, "PCAP malign para generador")

    def run_block(xdp_label: str):
        for pps in PPS_STEPS:
            print(f"[INFO] TRAFICO_ETH | XDP={xdp_label} | PPS objetivo = {pps}")

            tag = f"{xdp_label}_pps{pps}_{now_tag()}"
            pcap_out = os.path.join(pcaps_dir, f"rx_{tag}.pcap")
            tcpdump_log = os.path.join(logs_dir, f"tcpdump_{tag}.log")
            tcpdump_pid = os.path.join(logs_dir, f"tcpdump_{tag}.pid")
            gen_log = os.path.join(logs_dir, f"gen_{tag}.log")

            start_bg(
                hdst,
                f"timeout {GEN_DURATION} tcpdump -i {shlex.quote(rx_iface)} -n -U -s 0 -w {shlex.quote(pcap_out)}",
                tcpdump_pid,
                tcpdump_log,
            )
            time.sleep(0.6)

            cmd = (
                f"python3 {shlex.quote(gen_script)} "
                f"--legit {shlex.quote(legit_abs)} "
                f"--mal {shlex.quote(mal_abs)} "
                f"--duration {GEN_DURATION} "
                f"--burst-ms {GEN_BURST_MS} "
                f"--p-mal {GEN_P_MAL} "
                f"--rate {int(pps)} "
                f"--batch {GEN_BATCH} "
                f"--iface {shlex.quote(tx_iface)} "
                f"--src-mac {src_mac} "
                f"--dst-mac {dst_mac} "
                f"--dst-ip {shlex.quote(hdst_ip)} "
                f"--seed {GEN_SEED}"
            )
            out = run_cmd(hsrc, f"{cmd} 2>&1 | tee {shlex.quote(gen_log)}")
            time.sleep(1.0)

            tx = parse_gen_stdout(out)
            tx_total = tx["tx_total"]

            rx_pkts = count_pcap_packets(hdst, pcap_out)
            pps_measured = (rx_pkts / float(GEN_DURATION)) if GEN_DURATION > 0 else 0.0

            lost = max(0, tx_total - rx_pkts)
            loss_percent = (lost / tx_total * 100.0) if tx_total > 0 else 0.0

            note = "" if tx_total > 0 else "gen_sent_0 (ver gen log)"

            row = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "xdp": xdp_label,
                "label": "trafico_eth",
                "pps_target": pps,
                "pps_measured": f"{pps_measured:.2f}",
                "bps_measured": "0.00",
                "lost_percent": f"{loss_percent:.2f}",
                "lost_packets": lost,
                "packets_total": rx_pkts,
                "tx_packets_total": tx_total,
                "tx_legit_packets": tx["tx_legit"],
                "tx_mal_packets": tx["tx_mal"],
                "note": note,
            }

            write_header = not os.path.exists(csv_path)
            with open(csv_path, "a", newline="") as f:
                w = csv.DictWriter(f, fieldnames=header)
                if write_header:
                    w.writeheader()
                w.writerow(row)

            time.sleep(SLEEP_BETWEEN_RUNS)

    print("[INFO] trafico_eth SIN XDP")
    run_block("off")

    time.sleep(SLEEP_BETWEEN_BLOCKS)

    xdp_pid = os.path.join(base_dir, "xdp_usr_trafico_eth.pid")
    xdp_log = os.path.join(base_dir, "xdp_usr_trafico_eth.log")

    print(f"[INFO] Activando XDP en {rx_iface} (trafico_eth)")
    start_xdp(hdst, repo_root, rx_iface, xdp_pid, xdp_log)

    try:
        print("[INFO] trafico_eth CON XDP")
        run_block("on")
    finally:
        print("[INFO] Desactivando XDP (trafico_eth)")
        stop_bg(hdst, xdp_pid)


# ======================================================
# MAIN
# ======================================================

def main():
    if os.geteuid() != 0:
        raise SystemExit("Este script debe ejecutarse como root (sudo).")

    ap = argparse.ArgumentParser(
        description="Suite Mininet v8: iperf + tcpreplay(legit/malign) + trafico_eth (fix tcprewrite/tcpreplay)"
    )
    ap.add_argument("--repo-root", required=True, help="Ruta absoluta al root del repo")
    ap.add_argument("-l", "--legit", dest="pcap_legit", required=True,
                    help="PCAP legítimo (ABSOLUTO recomendado)")
    ap.add_argument("-m", "--malign", dest="pcap_malign", required=True,
                    help="PCAP maligno (ABSOLUTO recomendado)")

    ap.add_argument("--skip-iperf", action="store_true")
    ap.add_argument("--skip-tcpreplay", action="store_true")
    ap.add_argument("--skip-generator", action="store_true")

    args = ap.parse_args()

    # Resolver y validar PCAPs desde YA (evita runs largos inútiles)
    legit_abs = abspath(args.repo_root, args.pcap_legit)
    malign_abs = abspath(args.repo_root, args.pcap_malign)
    must_exist_file(legit_abs, "PCAP legítimo")
    must_exist_file(malign_abs, "PCAP maligno")

    suite_dir = f"/tmp/exp_suite_{now_tag()}"
    iperf_dir = os.path.join(suite_dir, "iperf")
    tcpr_dir = os.path.join(suite_dir, "tcpreplay")
    gen_dir = os.path.join(suite_dir, "generator")
    os.makedirs(iperf_dir, exist_ok=True)
    os.makedirs(tcpr_dir, exist_ok=True)
    os.makedirs(gen_dir, exist_ok=True)

    net = Mininet(
        topo=SimpleTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    net.start()
    try:
        print("[INFO] Mininet arrancado correctamente")
        print(f"[INFO] Suite resultados en: {suite_dir}")

        preflight(net, suite_dir)

        if not args.skip_iperf:
            print("[INFO] ====== FASE 1: IPERF ======")
            iperf_sweep(net, iperf_dir, args.repo_root)
            print("[INFO] Esperando entre fases para limpiar estado…")
            time.sleep(SLEEP_BETWEEN_EXPERIMENTS)

        if not args.skip_tcpreplay:
            print("[INFO] ====== FASE 2: TCPREPLAY (legit/malign) ======")
            tcpreplay_sweep(net, tcpr_dir, args.repo_root, args.pcap_legit, label="legit")
            time.sleep(SLEEP_BETWEEN_EXPERIMENTS)
            tcpreplay_sweep(net, tcpr_dir, args.repo_root, args.pcap_malign, label="malign")
            print("[INFO] Esperando entre fases para limpiar estado…")
            time.sleep(SLEEP_BETWEEN_EXPERIMENTS)

        if not args.skip_generator:
            print("[INFO] ====== FASE 3: TRAFICO_ETH ======")
            trafico_eth_sweep(net, gen_dir, args.repo_root, args.pcap_legit, args.pcap_malign)

    finally:
        net.stop()
        print(f"[INFO] Resultados en: {suite_dir}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
