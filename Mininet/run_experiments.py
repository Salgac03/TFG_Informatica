#!/usr/bin/env python3
import argparse
import os
import shlex
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

# Importa TU topología sin duplicarla
from redarbolrw1 import SimpleTopo


def abspath(repo_root: str, path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(repo_root, path)


def now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(host, path: str):
    host.cmd(f"mkdir -p {shlex.quote(path)}")


def run_cmd(host, cmd: str, log_path: str | None = None) -> str:
    """
    Ejecuta cmd en el host (namespace Mininet). Si log_path se pasa, redirige stdout/stderr ahí.
    Devuelve stdout (si no rediriges) o string vacío (si rediriges).
    """
    if log_path:
        return host.cmd(f"{cmd} > {shlex.quote(log_path)} 2>&1")
    return host.cmd(cmd)


def start_bg(host, cmd: str, pidfile: str, log_path: str):
    """
    Lanza cmd en background en el host, guarda PID en pidfile, log a log_path.
    """
    qpid = shlex.quote(pidfile)
    qlog = shlex.quote(log_path)
    host.cmd(f"{cmd} > {qlog} 2>&1 & echo $! > {qpid}")


def stop_bg(host, pidfile: str):
    host.cmd(f"kill $(cat {shlex.quote(pidfile)}) >/dev/null 2>&1 || true")


def ping_sanity(net):
    out = net["hsrc"].cmd("ping -c 1 10.0.1.2")
    print(out)


def tcpreplay_test(net, repo_root, pcap, duration, ctrl_port, prefix, reps, results_dir):
    scripts_dir = os.path.join(repo_root, "Pruebas", "nuevas_pruebas")
    rx_script = os.path.join(scripts_dir, "rx_capture_server.sh")
    runner_script = os.path.join(scripts_dir, "run_tcpreplay_pps.sh")

    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)

    # Receptor tcpdump (escucha control + captura)
    rx_log = os.path.join(results_dir, f"rx_capture_{prefix}_{now_tag()}.log")
    rx_pid = os.path.join(results_dir, "rx_capture.pid")

    # OJO: rx_capture_server escribe CSVs en el OUT_DIR que le pasas (results_dir)
    start_bg(
        hdst,
        f"chmod +x {shlex.quote(rx_script)} {shlex.quote(runner_script)} >/dev/null 2>&1 || true; "
        f"{shlex.quote(rx_script)} hdst-eth0 {shlex.quote(results_dir)} {ctrl_port}",
        rx_pid,
        rx_log,
    )
    time.sleep(0.5)

    # Runner en hsrc (barre PPS y manda START al receptor)
    runner_log = os.path.join(results_dir, f"runner_{prefix}_{now_tag()}.log")
    pcap_abs = abspath(repo_root, pcap)
    cmd_runner = (
        f"chmod +x {shlex.quote(runner_script)} >/dev/null 2>&1 || true; "
        f"{shlex.quote(runner_script)} hsrc-eth0 {shlex.quote(pcap_abs)} {duration} 10.0.1.2 {ctrl_port} "
        f"{shlex.quote(prefix)} {reps}"
    )
    run_cmd(hsrc, cmd_runner, runner_log)

    # Parar receptor
    stop_bg(hdst, rx_pid)
    print(f"[OK] TCPReplay: CSVs y logs en {results_dir}")


def iperf_test(net, results_dir, duration, parallel, reverse, udp, bitrate):
    """
    iperf3: servidor en hdst, cliente en hsrc. Guarda logs.
    - UDP opcional con --udp y --bitrate
    - reverse opcional (--reverse)
    - parallel opcional (-P)
    """
    hsrc, hdst = net["hsrc"], net["hdst"]
    ensure_dir(hdst, results_dir)
    ensure_dir(hsrc, results_dir)

    srv_log = os.path.join(results_dir, f"iperf3_server_{now_tag()}.log")
    srv_pid = os.path.join(results_dir, "iperf3_server.pid")
    cli_log = os.path.join(results_dir, f"iperf3_client_{now_tag()}.log")

    # Arranca servidor
    start_bg(hdst, "iperf3 -s", srv_pid, srv_log)
    time.sleep(0.5)

    # Cliente
    args = []
    args += ["-c", "10.0.1.2"]
    args += ["-t", str(duration)]
    if parallel and parallel > 1:
        args += ["-P", str(parallel)]
    if reverse:
        args += ["--reverse"]
    if udp:
        args += ["-u"]
        if bitrate:
            args += ["-b", str(bitrate)]

    cmd_cli = "iperf3 " + " ".join(shlex.quote(a) for a in args)
    run_cmd(hsrc, cmd_cli, cli_log)

    # Para servidor
    stop_bg(hdst, srv_pid)

    print(f"[OK] iPerf3: logs en {results_dir} (client/server).")


def custom_test(net, repo_root, script_path, args, results_dir):
    """
    Ejecuta tu script (en hsrc normalmente) y guarda stdout/stderr.
    Si tu script necesita receptor, lo ideal es que lo gestione internamente o reutilice el rx_capture_server.
    """
    hsrc = net["hsrc"]
    ensure_dir(hsrc, results_dir)

    script_abs = abspath(repo_root, script_path)
    log_path = os.path.join(results_dir, f"custom_{now_tag()}.log")
    cmd = " ".join([shlex.quote(script_abs)] + [shlex.quote(a) for a in args])

    # Asegura ejecutable
    hsrc.cmd(f"chmod +x {shlex.quote(script_abs)} >/dev/null 2>&1 || true")
    run_cmd(hsrc, cmd, log_path)

    print(f"[OK] Custom: log en {log_path}")


def main():
    ap = argparse.ArgumentParser(description="Runner de experimentos Mininet (DRY): tcpreplay, iperf, custom")
    ap.add_argument("--repo-root", required=True, help="Ruta absoluta al root del repo")
    ap.add_argument("--results-dir", default=None, help="Directorio resultados (por defecto /tmp/exp_<timestamp>)")
    ap.add_argument("--keep-alive", action="store_true", help="Mantener la red viva al final (Ctrl+C para salir)")

    sub = ap.add_subparsers(dest="mode", required=True)

    # tcpreplay
    ap_t = sub.add_parser("tcpreplay", help="Ejecuta rx_capture_server + runner tcpreplay sweep")
    ap_t.add_argument("--pcap", required=True, help="Ruta al PCAP (abs o relativa al repo)")
    ap_t.add_argument("--duration", type=int, default=10)
    ap_t.add_argument("--ctrl-port", type=int, default=5555)
    ap_t.add_argument("--prefix", default="tcpreplay")
    ap_t.add_argument("--reps", type=int, default=1)

    # iperf
    ap_i = sub.add_parser("iperf", help="Ejecuta iperf3 server/client y guarda logs")
    ap_i.add_argument("--duration", type=int, default=10)
    ap_i.add_argument("--parallel", type=int, default=1)
    ap_i.add_argument("--reverse", action="store_true")
    ap_i.add_argument("--udp", action="store_true")
    ap_i.add_argument("--bitrate", default=None, help="Solo UDP, ej: 100M, 1G")

    # custom
    ap_c = sub.add_parser("custom", help="Ejecuta tu script propio (en hsrc) y guarda log")
    ap_c.add_argument("--script", required=True, help="Ruta script (abs o relativa al repo)")
    ap_c.add_argument("args", nargs=argparse.REMAINDER, help="Argumentos extra para tu script (pon -- antes)")

    args = ap.parse_args()
    repo_root = args.repo_root

    results_dir = args.results_dir
    if not results_dir:
        results_dir = f"/tmp/exp_{args.mode}_{now_tag()}"

    # Construir red
    net = Mininet(
        topo=SimpleTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False
    )

    net.start()
    try:
        ping_sanity(net)

        if args.mode == "tcpreplay":
            tcpreplay_test(
                net,
                repo_root=repo_root,
                pcap=args.pcap,
                duration=args.duration,
                ctrl_port=args.ctrl_port,
                prefix=args.prefix,
                reps=args.reps,
                results_dir=results_dir,
            )

        elif args.mode == "iperf":
            iperf_test(
                net,
                results_dir=results_dir,
                duration=args.duration,
                parallel=args.parallel,
                reverse=args.reverse,
                udp=args.udp,
                bitrate=args.bitrate,
            )

        elif args.mode == "custom":
            # args.args incluye lo que venga después; si el usuario pone "--", argparse lo conserva.
            extra = args.args
            if extra and extra[0] == "--":
                extra = extra[1:]
            custom_test(net, repo_root=repo_root, script_path=args.script, args=extra, results_dir=results_dir)

        if args.keep_alive:
            print("[INFO] keep-alive activo. Ctrl+C para terminar.")
            while True:
                time.sleep(1)

    finally:
        net.stop()
        print(f"[INFO] Resultados: {results_dir}")


if __name__ == "__main__":
    setLogLevel("info")
    main()
