#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
plot_exp_suite_8fig_noiperf.py

Genera 8 gráficas comparativas usando SOLO:
 - tcpreplay_legit_results.csv
 - tcpreplay_malign_results.csv
 - trafico_eth_results.csv

Permite:
  - --suite-dir <exp_suite_dir>  (autodetecta CSVs)
  - o rutas sueltas: --tcplegit --tcpmalign --gen

Leyendas fuera (derecha) para no tapar líneas.
"""

import argparse
import os
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------------------------
# Helpers de IO / discovery
# -------------------------------------------------

def read_csv(path):
    return pd.read_csv(path)

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def save(fig, base, fmt):
    fig.savefig(f"{base}.{fmt}", bbox_inches="tight", dpi=200)
    plt.close(fig)

def maybe_suite_paths(suite_dir: str):
    """
    Busca los CSVs asumiendo estructura típica del exp_suite:
      tcpreplay/legit/tcpreplay_legit_results.csv
      tcpreplay/malign/tcpreplay_malign_results.csv
      generator/trafico_eth/trafico_eth_results.csv
      generator/trafico_eth_results.csv (fallback)
    """
    suite = Path(suite_dir)

    tcplegit = suite / "tcpreplay" / "legit" / "tcpreplay_legit_results.csv"
    tcpmalign = suite / "tcpreplay" / "malign" / "tcpreplay_malign_results.csv"

    gen1 = suite / "generator" / "trafico_eth" / "trafico_eth_results.csv"
    gen2 = suite / "generator" / "trafico_eth_results.csv"

    return {
        "tcplegit": str(tcplegit) if tcplegit.exists() else None,
        "tcpmalign": str(tcpmalign) if tcpmalign.exists() else None,
        "gen": str(gen1) if gen1.exists() else (str(gen2) if gen2.exists() else None),
    }

# -------------------------------------------------
# Leyenda fuera
# -------------------------------------------------

def legend_outside(ax, fontsize=8):
    handles, labels = ax.get_legend_handles_labels()
    if handles:
        ax.legend(
            handles, labels,
            fontsize=fontsize,
            loc="center left",
            bbox_to_anchor=(1.02, 0.5),
            frameon=True
        )

# -------------------------------------------------
# Limpieza / métricas
# -------------------------------------------------

def prep(df):
    df = df.copy()

    if "xdp" in df.columns:
        df["xdp"] = df["xdp"].astype(str).str.strip().str.lower()

    # Convertir columnas relevantes a numérico si existen
    numeric_cols = [
        "pps_target", "pps_measured",
        "lost_percent", "lost_real_percent",
        "paquetes_filtrados", "paquetes_perdidos_reales",
        "packets_total", "lost_packets",
        "cpu_usage_percent", "mem_usage_percent",
    ]
    for c in numeric_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # Calcular lost_real_percent si falta o está vacío
    if "lost_real_percent" not in df.columns or not df["lost_real_percent"].notna().any():
        if "paquetes_perdidos_reales" in df.columns and "packets_total" in df.columns:
            denom = df["packets_total"].replace({0: pd.NA})
            df["lost_real_percent"] = (df["paquetes_perdidos_reales"] / denom) * 100.0

    # Goodput y gap
    if "pps_measured" in df.columns and "lost_real_percent" in df.columns:
        df["goodput_pps"] = df["pps_measured"] * (1 - df["lost_real_percent"] / 100.0)
    else:
        df["goodput_pps"] = pd.NA

    if "lost_percent" in df.columns and "lost_real_percent" in df.columns:
        df["loss_gap"] = df["lost_percent"] - df["lost_real_percent"]
    else:
        df["loss_gap"] = pd.NA

    return df

# -------------------------------------------------
# Plotters
# -------------------------------------------------

def plot_on_off(ax, df, x, y, label):
    for state in ("off", "on"):
        if "xdp" not in df.columns:
            continue
        sub = df[df["xdp"] == state].sort_values(x)
        if not sub.empty:
            ax.plot(sub[x], sub[y], marker="o", label=f"{label} | xdp {state}")

def plot_on(ax, df, x, y, label):
    if "xdp" not in df.columns:
        return
    sub = df[df["xdp"] == "on"].sort_values(x)
    if not sub.empty:
        ax.plot(sub[x], sub[y], marker="o", label=f"{label} | xdp on")

# -------------------------------------------------
# Main
# -------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite-dir", default=None, help="Directorio exp_suite (autodetecta CSVs)")
    ap.add_argument("--tcplegit", default=None, help="Ruta a tcpreplay_legit_results.csv")
    ap.add_argument("--tcpmalign", default=None, help="Ruta a tcpreplay_malign_results.csv")
    ap.add_argument("--gen", default=None, help="Ruta a trafico_eth_results.csv")
    ap.add_argument("--out", default=None, help="Directorio de salida (default: <suite-dir>/plots_8 o ./plots_8)")
    ap.add_argument("--fmt", default="png", choices=["png", "pdf"])
    args = ap.parse_args()

    tcplegit = args.tcplegit
    tcpmalign = args.tcpmalign
    gen = args.gen

    # Si dan suite-dir, intenta autodetectar
    if args.suite_dir:
        found = maybe_suite_paths(args.suite_dir)
        tcplegit = tcplegit or found["tcplegit"]
        tcpmalign = tcpmalign or found["tcpmalign"]
        gen = gen or found["gen"]
        out_dir = args.out or str(Path(args.suite_dir) / "plots_8")
    else:
        out_dir = args.out or str(Path.cwd() / "plots_8")

    # Validación
    if not (tcplegit and tcpmalign and gen):
        raise SystemExit(
            "Faltan CSVs. Necesito:\n"
            "  --tcplegit <...> --tcpmalign <...> --gen <...>\n"
            "o usar --suite-dir <...>.\n"
            f"legit={tcplegit}\nmalign={tcpmalign}\ngen={gen}"
        )

    for p in (tcplegit, tcpmalign, gen):
        if not os.path.isfile(p):
            raise SystemExit(f"No existe: {p}")

    ensure_dir(out_dir)

    dl = prep(read_csv(tcplegit))
    dm = prep(read_csv(tcpmalign))
    dg = prep(read_csv(gen))

    x = "pps_target"

    figures = [
        ("01_loss_aparente", "Loss APARENTE (%) vs PPS target (XDP off/on)", "lost_percent", plot_on_off),
        ("02_loss_real", "Loss REAL (%) vs PPS target (XDP off/on)", "lost_real_percent", plot_on_off),
        ("03_pps_measured", "PPS measured vs PPS target (XDP off/on)", "pps_measured", plot_on_off),
        ("04_filtrados", "Paquetes filtrados (XDP_DROP) vs PPS target (solo XDP ON)", "paquetes_filtrados", plot_on),
        ("05_cpu", "CPU usage (%) vs PPS target (XDP off/on)", "cpu_usage_percent", plot_on_off),
        ("06_ram", "RAM usage (%) vs PPS target (XDP off/on)", "mem_usage_percent", plot_on_off),
        ("07_goodput", "Goodput (pps útiles) vs PPS target (XDP off/on)", "goodput_pps", plot_on_off),
        ("08_gap_loss", "Gap pérdida (aparente - real) vs PPS target (solo XDP ON)", "loss_gap", plot_on),
    ]

    for name, title, col, fn in figures:
        fig, ax = plt.subplots(figsize=(9.5, 5))
        fn(ax, dl, x, col, "tcpreplay_legit")
        fn(ax, dm, x, col, "tcpreplay_malign")
        fn(ax, dg, x, col, "trafico_eth")

        ax.set_title(title)
        ax.set_xlabel("pps_target")
        ax.set_ylabel(col)

        legend_outside(ax, fontsize=8)

        save(fig, str(Path(out_dir) / name), args.fmt)

    print(f"[OK] Gráficas generadas en: {out_dir}")


if __name__ == "__main__":
    main()
