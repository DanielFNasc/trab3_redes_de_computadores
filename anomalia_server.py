#!/usr/bin/env python3
"""
Servidor de testes do Trabalho 3 (fluxo elefante em P4). Executar em H3:

    mininet> h3 python3 anomalia_server.py > /tmp/anom_server.txt 2>&1 &

Serviços (todos em 200.0.0.2):
    UDP 9101  dados     - conta bytes/pacotes por (run, host) e por segundo
    TCP 9102  dados     - idem, para o elefante TCP
    UDP 9103  eco       - devolve o pacote (medida de RTT feita pelo cliente)

Como os pacotes chegam com o IP traduzido pelo NAT (200.0.0.1), o host de
origem é identificado pelo cabeçalho que o cliente coloca no payload.

Cada inicialização começa uma sessão nova: o diretório anom_obs/ (ao lado
deste script) é limpo. Os resultados do servidor ficam em
anom_obs/server_run<N>.json. Apenas biblioteca padrão.
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

DEFAULT_BIND = "200.0.0.2"
UDP_DATA_PORT = 9101
TCP_DATA_PORT = 9102
ECHO_PORT = 9103

# Cabeçalho dos pacotes de dados e de sondagem: run, id do host, seq, t_envio_ns
HDR = struct.Struct("!HBIQ")
# Primeira mensagem de uma conexão TCP: run, id do host
HELLO = struct.Struct("!HB")

HOST_NAME = {1: "h1", 2: "h2"}

DEFAULT_OBS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "anom_obs"
)


def to_ranges(seqs):
    """Converte um conjunto de números de sequência em faixas [ini, fim]."""
    out = []
    start = prev = None
    for s in sorted(seqs):
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            out.append([start, prev])
            start = prev = s
    if start is not None:
        out.append([start, prev])
    return out


class Collector:
    """Acumula o que chegou em H3 e grava em JSON periodicamente."""

    def __init__(self, obs_dir):
        self.obs_dir = obs_dir
        self.lock = threading.Lock()
        self.runs = {}
        self.dirty = set()
        self.log_lock = threading.Lock()

    def log(self, text):
        line = time.strftime("%H:%M:%S ") + text
        with self.log_lock:
            print(line, flush=True)
            try:
                with open(os.path.join(self.obs_dir, "server.log"), "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def add(self, run, kind, host, nbytes, seq=None):
        now = time.time()
        sec = str(int(now))
        with self.lock:
            runrec = self.runs.setdefault(run, {"udp": {}, "tcp": {}})
            rec = runrec[kind].get(host)
            if rec is None:
                rec = {
                    "bytes": 0, "pkts": 0, "first": now, "last": now,
                    "bytes_by_sec": {}, "pkts_by_sec": {}, "seqs": set(),
                }
                runrec[kind][host] = rec
                self.log("[%s] run %d: primeiro dado de %s" % (kind.upper(), run, host.upper()))
            rec["bytes"] += nbytes
            rec["last"] = now
            rec["bytes_by_sec"][sec] = rec["bytes_by_sec"].get(sec, 0) + nbytes
            if seq is not None:
                rec["pkts"] += 1
                rec["pkts_by_sec"][sec] = rec["pkts_by_sec"].get(sec, 0) + 1
                rec["seqs"].add(seq)
            self.dirty.add(run)

    def flush(self):
        with self.lock:
            runs = sorted(self.dirty)
            self.dirty = set()
            snap = {}
            for run in runs:
                snap[run] = {}
                for kind, hosts in self.runs[run].items():
                    snap[run][kind] = {}
                    for host, rec in hosts.items():
                        snap[run][kind][host] = {
                            "bytes": rec["bytes"],
                            "pkts": rec["pkts"],
                            "first": rec["first"],
                            "last": rec["last"],
                            "bytes_by_sec": dict(rec["bytes_by_sec"]),
                            "pkts_by_sec": dict(rec["pkts_by_sec"]),
                            "seqs": set(rec["seqs"]),
                        }
        for run, kinds in snap.items():
            out = {"run": run, "updated": time.time(), "udp": {}, "tcp": {}}
            for kind, hosts in kinds.items():
                for host, rec in hosts.items():
                    rec["seq_ranges"] = to_ranges(rec.pop("seqs"))
                    out[kind][host] = rec
            final = os.path.join(self.obs_dir, "server_run%d.json" % run)
            tmp = final + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump(out, f)
                os.replace(tmp, final)
            except OSError as exc:
                self.log("[ERRO] gravando %s: %s" % (final, exc))

    def flusher(self):
        while True:
            time.sleep(1.0)
            self.flush()


def udp_data_loop(sock, col):
    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except OSError:
            continue
        if len(data) < HDR.size:
            continue
        run, hid, seq, _ = HDR.unpack_from(data)
        host = HOST_NAME.get(hid)
        if host is None:
            continue
        col.add(run, "udp", host, len(data), seq)


def echo_loop(sock):
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)
        except OSError:
            continue


def tcp_conn(conn, addr, col):
    with conn:
        try:
            conn.settimeout(30)
            buf = b""
            while len(buf) < HELLO.size:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            run, hid = HELLO.unpack_from(buf)
            host = HOST_NAME.get(hid)
            if host is None:
                return
            col.log("[TCP] run %d: conexão de %s (%s:%d)" % (run, host.upper(), addr[0], addr[1]))
            rest = buf[HELLO.size:]
            if rest:
                col.add(run, "tcp", host, len(rest))
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                col.add(run, "tcp", host, len(chunk))
            col.log("[TCP] run %d: %s encerrou a conexão" % (run, host.upper()))
        except OSError as exc:
            col.log("[TCP] erro na conexão de %s:%d: %s" % (addr[0], addr[1], exc))


def tcp_loop(lsock, col):
    while True:
        try:
            conn, addr = lsock.accept()
        except OSError:
            continue
        threading.Thread(target=tcp_conn, args=(conn, addr, col), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="Servidor de testes do Trabalho 3 (executar em H3).")
    ap.add_argument("--bind", default=DEFAULT_BIND,
                    help="IP de escuta (padrão: %(default)s; use 127.0.0.1 para testar localmente)")
    ap.add_argument("--obs-dir", default=DEFAULT_OBS_DIR,
                    help="diretório compartilhado com os clientes (padrão: %(default)s)")
    ap.add_argument("--no-clean", action="store_true",
                    help="não limpar o diretório de observações ao iniciar")
    args = ap.parse_args()

    obs_dir = os.path.abspath(args.obs_dir)
    os.makedirs(obs_dir, exist_ok=True)
    if not args.no_clean:
        for name in os.listdir(obs_dir):  # nova sessão
            if name.endswith((".json", ".tmp", ".log", ".csv", ".png")):
                try:
                    os.remove(os.path.join(obs_dir, name))
                except OSError:
                    pass

    col = Collector(obs_dir)
    col.log("=== Servidor de testes do Trabalho 3 (H3) ===")

    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        udp.bind((args.bind, UDP_DATA_PORT))
        echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        echo.bind((args.bind, ECHO_PORT))
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((args.bind, TCP_DATA_PORT))
        tcp.listen(20)
    except OSError as exc:
        col.log("[ERRO] não foi possível abrir as portas em %s: %s" % (args.bind, exc))
        col.log("       Verifique se o script está rodando em H3.")
        sys.exit(1)

    with open(os.path.join(obs_dir, "server_status.json"), "w") as f:
        json.dump({"started": time.time(), "bind": args.bind}, f)

    col.log("UDP %s:%d | TCP %s:%d | eco %s:%d | observações em %s"
            % (args.bind, UDP_DATA_PORT, args.bind, TCP_DATA_PORT,
               args.bind, ECHO_PORT, obs_dir))

    for target, targs in (
        (udp_data_loop, (udp, col)),
        (echo_loop, (echo,)),
        (col.flusher, ()),
    ):
        threading.Thread(target=target, args=targs, daemon=True).start()

    try:
        tcp_loop(tcp, col)
    except KeyboardInterrupt:
        pass
    finally:
        col.flush()


if __name__ == "__main__":
    main()

