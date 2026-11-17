#!/usr/bin/env python3
"""
Plano de controle do Trabalho 3: configura o detector do switch S1 e lê os
contadores dele, usando o simple_switch_CLI (Thrift, porta 9090 por padrão).

Executar no CLI do Mininet com "sh" (roda fora dos hosts, na máquina onde o
switch está):

    mininet> sh python3 anomalia_ctl.py prepare --mode total
    mininet> sh python3 anomalia_ctl.py stats --run 3
    mininet> sh python3 anomalia_ctl.py show

Subcomandos:
    mode {off,total,prob,limit}
                            troca a estratégia (off = só detecta, sem descartar;
                            limit = limitador por janela)
    thresh BYTES            limiar em bytes por janela de 100 ms (0 = padrão do P4)
    reset                   zera detector, contadores e o estado do NAT
    prepare --mode M        reset + mode (+ --thresh) : começo de cada execução
    stats --run N           lê os registradores e grava anom_obs/switch_run<N>.json
    show                    mostra a configuração e o estado atual

Se o switch não estiver na porta 9090, use --thrift-port (ou a variável de
ambiente THRIFT_PORT). Apenas biblioteca padrão.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

PREFIX = "MyIngress."
MODES = {"off": 0, "total": 1, "prob": 2, "limit": 3}
MODE_NAME = {v: k for k, v in MODES.items()}

DEFAULT_OBS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "anom_obs"
)

# Registradores por host (índice = último octeto do IP privado)
HOST_REGS = [
    "det_state", "det_level", "det_alarms",
    "det_first_seen", "det_first_alarm", "det_last_clear",
    "stat_pass_pkts", "stat_drop_pkts", "stat_pass_bytes", "stat_drop_bytes",
]
RESET_REGS = [
    "det_win_start", "det_win_bytes", "det_state", "det_level",
    "det_first_seen", "det_first_alarm", "det_last_clear", "det_alarms",
    "stat_pass_pkts", "stat_drop_pkts", "stat_pass_bytes", "stat_drop_bytes",
    "nat_owner_ip", "nat_owner_port",
]
HOSTS = {1: "h1", 2: "h2"}


def run_cli(cmds, port):
    try:
        proc = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(port)],
            input="\n".join(cmds) + "\n",
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        sys.exit("[ERRO] simple_switch_CLI não encontrado no PATH.")
    except subprocess.TimeoutExpired:
        sys.exit("[ERRO] simple_switch_CLI não respondeu (porta Thrift %d correta?)." % port)
    out = proc.stdout + proc.stderr
    if "Could not connect" in out or "Connection refused" in out:
        sys.exit("[ERRO] não foi possível conectar ao switch na porta Thrift %d.\n"
                 "       Descubra a porta com: sudo ss -ltnp | grep simple_switch\n"
                 "       e use --thrift-port." % port)
    return out


def read_regs(port, names_idx):
    """names_idx: lista de (registrador, índice). Retorna lista de inteiros."""
    cmds = ["register_read %s%s %d" % (PREFIX, n, i) for n, i in names_idx]
    out = run_cli(cmds, port)
    vals = [int(v) for _, v in re.findall(r"\[(\d+)\]\s*=\s*(\d+)", out)]
    if len(vals) != len(names_idx):
        sys.exit("[ERRO] resposta inesperada do simple_switch_CLI (%d valores para %d leituras):\n%s"
                 % (len(vals), len(names_idx), out))
    return vals


def read_config(port):
    mode, thresh = read_regs(port, [("cfg_mode", 0), ("cfg_thresh", 0)])
    return mode, thresh


def read_hosts(port):
    queries = [(r, h) for h in HOSTS for r in HOST_REGS]
    vals = read_regs(port, queries)
    hosts = {}
    k = 0
    for h in HOSTS:
        rec = {}
        for r in HOST_REGS:
            rec[r] = vals[k]
            k += 1
        offered = rec["stat_pass_pkts"] + rec["stat_drop_pkts"]
        rec["offered_pkts"] = offered
        rec["drop_pct"] = (100.0 * rec["stat_drop_pkts"] / offered) if offered else 0.0
        if rec["det_first_alarm"] and rec["det_first_seen"]:
            rec["detect_ms"] = (rec["det_first_alarm"] - rec["det_first_seen"]) / 1000.0
        else:
            rec["detect_ms"] = None
        hosts[str(h)] = rec
    return hosts


def print_state(mode, thresh, hosts):
    thr = thresh if thresh else "padrão do P4 (50000)"
    print("Configuração: modo=%s (%d), limiar=%s bytes/janela" % (MODE_NAME.get(mode, "?"), mode, thr))
    for h, name in HOSTS.items():
        r = hosts[str(h)]
        estado = "ELEFANTE (nível %d)" % r["det_level"] if r["det_state"] else "normal"
        det = "%.1f ms" % r["detect_ms"] if r["detect_ms"] is not None else "-"
        print("  %s: estado=%s | alarmes=%d | detecção=%s | pacotes ok=%d descartados=%d (%.1f%%)"
              % (name.upper(), estado, r["det_alarms"], det,
                 r["stat_pass_pkts"], r["stat_drop_pkts"], r["drop_pct"]))


def cmd_mode(args):
    run_cli(["register_write %scfg_mode 0 %d" % (PREFIX, MODES[args.mode])], args.thrift_port)
    print("modo de tratamento: %s" % args.mode)


def cmd_thresh(args):
    run_cli(["register_write %scfg_thresh 0 %d" % (PREFIX, args.bytes)], args.thrift_port)
    print("limiar: %s bytes/janela" % (args.bytes or "padrão"))


def do_reset(port):
    run_cli(["register_reset %s%s" % (PREFIX, r) for r in RESET_REGS], port)


def cmd_reset(args):
    do_reset(args.thrift_port)
    print("detector, contadores e NAT zerados")


def cmd_prepare(args):
    cmds = ["register_reset %s%s" % (PREFIX, r) for r in RESET_REGS]
    cmds.append("register_write %scfg_mode 0 %d" % (PREFIX, MODES[args.mode]))
    cmds.append("register_write %scfg_thresh 0 %d" % (PREFIX, args.thresh))
    run_cli(cmds, args.thrift_port)
    mode, thresh = read_config(args.thrift_port)
    ok = (mode == MODES[args.mode]) and (thresh == args.thresh)
    print("preparado: modo=%s limiar=%s bytes/janela%s"
          % (MODE_NAME.get(mode, "?"), thresh or "padrão", "" if ok else "  [AVISO: leitura diferente da escrita]"))


def cmd_show(args):
    mode, thresh = read_config(args.thrift_port)
    print_state(mode, thresh, read_hosts(args.thrift_port))


def cmd_stats(args):
    mode, thresh = read_config(args.thrift_port)
    hosts = read_hosts(args.thrift_port)
    print("--- Switch, execução %d ---" % args.run)
    print_state(mode, thresh, hosts)
    obs_dir = os.path.abspath(args.obs_dir)
    os.makedirs(obs_dir, exist_ok=True)
    final = os.path.join(obs_dir, "switch_run%d.json" % args.run)
    with open(final, "w") as f:
        json.dump({"run": args.run, "time": time.time(),
                   "mode": mode, "mode_name": MODE_NAME.get(mode, "?"),
                   "thresh": thresh, "hosts": hosts}, f, indent=1)
    print("gravado em %s" % final)


def main():
    ap = argparse.ArgumentParser(description="Controle do detector de elefantes (S1).",
                                 epilog=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--thrift-port", type=int,
                    default=int(os.environ.get("THRIFT_PORT", "9090")))
    ap.add_argument("--obs-dir", default=DEFAULT_OBS_DIR)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("mode"); p.add_argument("mode", choices=MODES); p.set_defaults(fn=cmd_mode)
    p = sub.add_parser("thresh"); p.add_argument("bytes", type=int); p.set_defaults(fn=cmd_thresh)
    p = sub.add_parser("reset"); p.set_defaults(fn=cmd_reset)
    p = sub.add_parser("prepare")
    p.add_argument("--mode", choices=MODES, required=True)
    p.add_argument("--thresh", type=int, default=0, help="bytes por janela (0 = padrão)")
    p.set_defaults(fn=cmd_prepare)
    p = sub.add_parser("stats"); p.add_argument("--run", type=int, required=True); p.set_defaults(fn=cmd_stats)
    p = sub.add_parser("show"); p.set_defaults(fn=cmd_show)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

