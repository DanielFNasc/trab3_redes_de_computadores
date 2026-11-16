// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

/********************************************************************
 * TRABALHO 3 - DETECÇÃO E TRATAMENTO DE FLUXOS ELEFANTE EM P4
 *
 * Este programa é o NAT do Trabalho 2 (inalterado) mais:
 *
 *   PASSO 1  Definição da anomalia (constantes DET_* abaixo)
 *   PASSO 2  Detector no data plane (registradores + janela de tempo)
 *   PASSO 3  Tratamento: descarte total OU descarte probabilístico,
 *            escolhido em tempo de execução (registrador cfg_mode)
 *
 * O detector roda ANTES do NAT, no sentido de saída (10.0.0.0/24 ->
 * fora). Nesse ponto o IP de origem ainda é o privado, então cada host
 * é identificado pelo último octeto do seu IP (H1 -> 1, H2 -> 2).
 ********************************************************************/

/********************************************************************
 * CONSTANTES
 ********************************************************************/

const bit<16> TYPE_IPV4 = 0x0800;

const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

// IP público do NAT = 200.0.0.1
const bit<32> NAT_PUBLIC_IP = 0xC8000001;


/********************************************************************
 * PASSO 1 - DEFINIÇÃO DA ANOMALIA (FLUXO ELEFANTE)
 *
 * Um host é "elefante" quando o volume que ele OFERECE ao switch passa
 * de DET_THRESH_DEFAULT bytes dentro de uma janela de DET_WINDOW_US.
 *
 * Gargalo S1-H3 = 10 Mbps  ->  125.000 bytes por janela de 100 ms.
 * Limiar = 40% da capacidade = 50.000 bytes / 100 ms (= 4 Mbps).
 *
 * Justificativa: com o enlace compartilhado, um único host acima de 40%
 * da capacidade já domina a fila do gargalo e degrada os demais.
 *
 * O limiar pode ser trocado sem recompilar (registrador cfg_thresh).
 * O valor 0 em cfg_thresh significa "usar o padrão abaixo".
 ********************************************************************/

const bit<48> DET_WINDOW_US      = 100000;   // janela de 100 ms
const bit<48> DET_WINDOW2_US     = 200000;   // 2 janelas (janela intermediária vazia)
const bit<32> DET_THRESH_DEFAULT = 50000;    // bytes por janela

// Modos de tratamento (registrador cfg_mode; padrão 0 = só detecta)
const bit<8> MODE_OFF   = 0;   // sem mitigação: classifica, mas encaminha tudo
const bit<8> MODE_TOTAL = 1;   // estratégia A: descarte total
const bit<8> MODE_PROB  = 2;   // estratégia B: descarte probabilístico

// Estratégia B: probabilidade de descarte = P/256, conforme a intensidade
//   nível 1: taxa entre 1x e 2x o limiar  -> 25%
//   nível 2: taxa entre 2x e 3x o limiar  -> 50%
//   nível 3: taxa acima de 3x o limiar    -> 75%
const bit<8> P_LVL1 = 64;
const bit<8> P_LVL2 = 128;
const bit<8> P_LVL3 = 192;


/********************************************************************
 * TIPOS
 ********************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/********************************************************************
 * HEADERS
 ********************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


/*
 * Cabeçalho TCP mínimo.
 *
 * dataOffset = 4 bits
 * reserved   = 3 bits
 * flags      = 9 bits
 *
 * Total = 16 bits
 */
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;

    bit<32> seqNo;
    bit<32> ackNo;

    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;

    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


/********************************************************************
 * METADATA
 ********************************************************************/

struct metadata {

    // Portas originais do pacote
    bit<16> srcPort;
    bit<16> dstPort;

    // Tamanho do segmento TCP
    // Calculado no Ingress para ser usado no checksum.
    bit<16> tcpLength;
}


/********************************************************************
 * CONJUNTO DE HEADERS
 ********************************************************************/

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}


/********************************************************************
 * PARSER
 ********************************************************************/

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    state start {
        transition parse_ethernet;
    }


    state parse_ethernet {

        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {

            TYPE_IPV4: parse_ipv4;

            default: accept;
        }
    }


    state parse_ipv4 {

        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {

            PROTO_TCP: parse_tcp;

            PROTO_UDP: parse_udp;

            // Outros protocolos seguem para o Ingress,
            // onde serão descartados.
            default: accept;
        }
    }


    state parse_tcp {

        packet.extract(hdr.tcp);

        transition accept;
    }


    state parse_udp {

        packet.extract(hdr.udp);

        transition accept;
    }
}


/********************************************************************
 * VERIFICAÇÃO DE CHECKSUM
 ********************************************************************/

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {

    apply {
        // Não é necessário verificar aqui para este trabalho.
    }
}


/********************************************************************
 * INGRESS
 ********************************************************************/

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    /*
     * ---------------- Estado dinâmico do NAT (Trabalho 2) ----------------
     *
     * Índice = porta PÚBLICA (+65536 se UDP, para TCP e UDP terem
     * espaços de portas separados).
     *
     *   nat_owner_ip[porta_publica]   = IP privado dono da porta
     *   nat_owner_port[porta_publica] = porta privada original
     */
    register<bit<32>>(131072) nat_owner_ip;
    register<bit<16>>(131072) nat_owner_port;

    /*
     * ---------------- PASSO 2: estado do detector ----------------
     *
     * Todos os arrays têm 256 posições e são indexados pelo último
     * octeto do IP de origem privado (H1 = 1, H2 = 2). Isso evita hash
     * e colisões: a topologia só tem dois hosts internos.
     *
     * Configuração (escrita pelo plano de controle com simple_switch_CLI):
     *   cfg_mode[0]   : 0 = sem mitigação, 1 = descarte total, 2 = probabilístico
     *   cfg_thresh[0] : limiar em bytes por janela (0 = usa DET_THRESH_DEFAULT)
     */
    register<bit<8>>(1)  cfg_mode;
    register<bit<32>>(1) cfg_thresh;

    // Estado por host
    register<bit<48>>(256) det_win_start;    // início da janela atual (us)
    register<bit<32>>(256) det_win_bytes;    // bytes OFERECIDOS na janela atual
    register<bit<8>>(256)  det_state;        // 0 = normal, 1 = elefante
    register<bit<8>>(256)  det_level;        // intensidade 0..3 (usada pela estratégia B)

    // Medição do tempo de detecção e histórico (para a avaliação)
    register<bit<48>>(256) det_first_seen;   // 1º pacote do host
    register<bit<48>>(256) det_first_alarm;  // 1ª vez que o host virou elefante
    register<bit<48>>(256) det_last_clear;   // última vez que voltou ao normal
    register<bit<32>>(256) det_alarms;       // nº de transições normal -> elefante

    // Contadores do que o switch fez de fato
    register<bit<32>>(256) stat_pass_pkts;
    register<bit<32>>(256) stat_drop_pkts;
    register<bit<32>>(256) stat_pass_bytes;
    register<bit<32>>(256) stat_drop_bytes;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* ---------- regras estáticas (ponto extra / port-forward) ---------- */

    action static_out(bit<16> public_port) {
        hdr.ipv4.srcAddr = NAT_PUBLIC_IP;
        if (hdr.tcp.isValid()) { hdr.tcp.srcPort = public_port; }
        if (hdr.udp.isValid()) { hdr.udp.srcPort = public_port; }
    }

    action static_in(ip4Addr_t private_ip, bit<16> private_port) {
        hdr.ipv4.dstAddr = private_ip;
        if (hdr.tcp.isValid()) { hdr.tcp.dstPort = private_port; }
        if (hdr.udp.isValid()) { hdr.udp.dstPort = private_port; }
    }

    table nat_out_static {
        key = {
            hdr.ipv4.srcAddr  : exact;
            meta.srcPort      : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = { static_out; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    table nat_in_static {
        key = {
            meta.dstPort      : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = { static_in; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    apply {
        // ---- variáveis do NAT (Trabalho 2) ----
        bit<32> base      = 0;
        bit<32> idx       = 0;
        bit<32> owner     = 0;
        bit<16> owner_prv = 0;
        bit<16> newPort   = 0;
        bit<16> alt       = 0;
        bool    ok        = true;

        // ---- variáveis do detector (Trabalho 3) ----
        bit<32> hidx      = 0;   // índice do host
        bit<48> ts_now    = 0;   // relógio do switch em microssegundos
        bit<48> wstart    = 0;
        bit<48> elapsed   = 0;
        bit<48> t48       = 0;
        bit<32> wbytes    = 0;
        bit<32> last      = 0;   // bytes da última janela fechada
        bit<32> pktlen    = 0;
        bit<32> c32       = 0;
        bit<32> thr       = 0;   // limiar efetivo
        bit<32> thr2      = 0;   // 2 x limiar
        bit<32> thr3      = 0;   // 3 x limiar
        bit<32> thr_out   = 0;   // limiar de saída (histerese) = 0,75 x limiar
        bit<8>  st        = 0;
        bit<8>  old_st    = 0;
        bit<8>  lvl       = 0;
        bit<8>  mode      = 0;
        bit<8>  rnd       = 0;
        bit<8>  p8        = 0;
        bool    drop_it   = false;

        if (!hdr.ipv4.isValid() || !(hdr.tcp.isValid() || hdr.udp.isValid())) {
            // não-IPv4, ICMP e qualquer outro protocolo: descarta
            drop();
        } else {

            if (hdr.tcp.isValid()) {
                meta.srcPort   = hdr.tcp.srcPort;
                meta.dstPort   = hdr.tcp.dstPort;
                meta.tcpLength = hdr.ipv4.totalLen - 16w20;
                base = 0;
            } else {
                meta.srcPort = hdr.udp.srcPort;
                meta.dstPort = hdr.udp.dstPort;
                base = 65536;
            }

            /* ======================= SAÍDA: 10.0.0.0/24 -> fora ======================= */
            if ((hdr.ipv4.srcAddr & 0xFFFFFF00) == 0x0A000000) {

                /************************************************************
                 * PASSO 2 - DETECTOR DE FLUXO ELEFANTE (por host, janela 100 ms)
                 *
                 * Conta os bytes que o host OFERECE ao switch, mesmo os que
                 * depois serão descartados. Assim o host só volta ao estado
                 * normal quando REDUZ a taxa que está tentando enviar.
                 ************************************************************/

                hidx = hdr.ipv4.srcAddr & 32w0xFF;

                // 2.1 configuração
                cfg_mode.read(mode, 0);
                cfg_thresh.read(thr, 0);
                if (thr == 0) { thr = DET_THRESH_DEFAULT; }
                thr2    = thr << 1;
                thr3    = thr2 + thr;
                thr_out = thr - (thr >> 2);

                // 2.2 estado atual do host
                det_win_start.read(wstart, hidx);
                det_win_bytes.read(wbytes, hidx);
                det_state.read(st, hidx);
                det_level.read(lvl, hidx);
                old_st  = st;
                ts_now  = standard_metadata.ingress_global_timestamp;
                elapsed = ts_now - wstart;
                pktlen  = standard_metadata.packet_length;

                det_first_seen.read(t48, hidx);
                if (t48 == 0) { det_first_seen.write(hidx, ts_now); }

                // 2.3 atualização da janela e classificação
                if (elapsed >= DET_WINDOW_US) {
                    // A janela anterior terminou: classifica com os bytes dela.
                    // Se passaram 2 janelas ou mais, a janela anterior ficou vazia.
                    if (elapsed >= DET_WINDOW2_US) { last = 0; } else { last = wbytes; }

                    if (last > thr) {
                        st = 1;
                        if (last > thr3)      { lvl = 3; }
                        else if (last > thr2) { lvl = 2; }
                        else                  { lvl = 1; }
                    } else if (last > thr_out) {
                        // faixa de histerese (0,75 x limiar .. limiar): mantém o estado
                        if (st == 1) { lvl = 1; }
                    } else {
                        // abaixo de 0,75 x limiar: volta ao normal
                        st  = 0;
                        lvl = 0;
                    }

                    wbytes = pktlen;       // abre a nova janela com este pacote
                    wstart = ts_now;
                } else {
                    wbytes = wbytes + pktlen;
                    // Detecção antecipada: não espera a janela fechar
                    if (st == 0 && wbytes > thr) {
                        st  = 1;
                        lvl = 1;
                    }
                }

                // 2.4 registro de transições (medição do tempo de detecção)
                if (st == 1 && old_st == 0) {
                    det_alarms.read(c32, hidx);
                    det_alarms.write(hidx, c32 + 1);
                    det_first_alarm.read(t48, hidx);
                    if (t48 == 0) { det_first_alarm.write(hidx, ts_now); }
                }
                if (st == 0 && old_st == 1) {
                    det_last_clear.write(hidx, ts_now);
                }

                det_win_start.write(hidx, wstart);
                det_win_bytes.write(hidx, wbytes);
                det_state.write(hidx, st);
                det_level.write(hidx, lvl);

                /************************************************************
                 * PASSO 3 - TRATAMENTO (só atua em host classificado como elefante)
                 *   mode 0: sem mitigação  (encaminha tudo)
                 *   mode 1: ESTRATÉGIA A   descarte total
                 *   mode 2: ESTRATÉGIA B   descarte probabilístico (p cresce
                 *                          com a intensidade da anomalia)
                 ************************************************************/
                if (st == 1) {
                    if (mode == MODE_TOTAL) {
                        drop_it = true;
                    } else if (mode == MODE_PROB) {
                        random(rnd, 8w0, 8w255);
                        if (lvl == 3)      { p8 = P_LVL3; }
                        else if (lvl == 2) { p8 = P_LVL2; }
                        else               { p8 = P_LVL1; }
                        if (rnd < p8) { drop_it = true; }
                    }
                }

                // contadores do que o switch realmente fez
                if (drop_it) {
                    stat_drop_pkts.read(c32, hidx);
                    stat_drop_pkts.write(hidx, c32 + 1);
                    stat_drop_bytes.read(c32, hidx);
                    stat_drop_bytes.write(hidx, c32 + pktlen);
                    ok = false;     // não passa pelo NAT nem pelo encaminhamento
                } else {
                    stat_pass_pkts.read(c32, hidx);
                    stat_pass_pkts.write(hidx, c32 + 1);
                    stat_pass_bytes.read(c32, hidx);
                    stat_pass_bytes.write(hidx, c32 + pktlen);
                }

                /* ----------- NAT de saída (Trabalho 2), só se não foi descartado ----------- */
                if (!drop_it) {

                    if (!nat_out_static.apply().hit) {

                        // 1ª tentativa: preservar a porta de origem
                        idx = base + (bit<32>)meta.srcPort;
                        nat_owner_ip.read(owner, idx);
                        nat_owner_port.read(owner_prv, idx);

                        if (owner == 0 || (owner == hdr.ipv4.srcAddr && owner_prv == meta.srcPort)) {
                            newPort = meta.srcPort;
                        } else {
                            // Conflito (outro host já usa essa porta pública):
                            // usa uma porta alternativa determinística.
                            alt = meta.srcPort ^ 16w0x8000;
                            idx = base + (bit<32>)alt;
                            nat_owner_ip.read(owner, idx);
                            nat_owner_port.read(owner_prv, idx);

                            if (owner == 0 || (owner == hdr.ipv4.srcAddr && owner_prv == meta.srcPort)) {
                                newPort = alt;
                            } else {
                                ok = false;
                            }
                        }

                        if (ok) {
                            // registra/atualiza o mapeamento porta_pública -> (IP, porta) privados
                            nat_owner_ip.write(idx, hdr.ipv4.srcAddr);
                            nat_owner_port.write(idx, meta.srcPort);

                            hdr.ipv4.srcAddr = NAT_PUBLIC_IP;
                            if (hdr.tcp.isValid()) { hdr.tcp.srcPort = newPort; }
                            if (hdr.udp.isValid()) { hdr.udp.srcPort = newPort; }
                        }
                    }
                }
            }

            /* ======================= VOLTA: fora -> 200.0.0.1 ======================= */
            else if (hdr.ipv4.dstAddr == NAT_PUBLIC_IP) {

                if (!nat_in_static.apply().hit) {
                    idx = base + (bit<32>)meta.dstPort;
                    nat_owner_ip.read(owner, idx);
                    nat_owner_port.read(owner_prv, idx);

                    if (owner == 0) {
                        ok = false;          // sem mapeamento: descarta
                    } else {
                        hdr.ipv4.dstAddr = owner;
                        if (hdr.tcp.isValid()) { hdr.tcp.dstPort = owner_prv; }
                        if (hdr.udp.isValid()) { hdr.udp.dstPort = owner_prv; }
                    }
                }
            }

            /* Tráfego externo que não é para o NAT: não encaminha */
            else {
                ok = false;
            }

            if (ok) {
                ipv4_lpm.apply();
            } else {
                drop();
            }
        }
    }
}


/********************************************************************
 * EGRESS
 ********************************************************************/

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    apply {

    }
}


/********************************************************************
 * CÁLCULO DOS CHECKSUMS
 ********************************************************************/

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {

    apply {


        /************************************************************
         * CHECKSUM IPv4
         ************************************************************/

        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },

            hdr.ipv4.hdrChecksum,

            HashAlgorithm.csum16
        );


        /************************************************************
         * CHECKSUM TCP
         *
         * Inclui pseudo-header IPv4 + header TCP + payload.
         ************************************************************/

        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                /*
                 * Pseudo-header IPv4
                 */
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLength,

                /*
                 * Cabeçalho TCP
                 */
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },

            hdr.tcp.checksum,

            HashAlgorithm.csum16
        );


        /************************************************************
         * CHECKSUM UDP
         *
         * Inclui pseudo-header IPv4 + header UDP + payload.
         ************************************************************/

        update_checksum_with_payload(
            hdr.udp.isValid(),
            {
                /*
                 * Pseudo-header IPv4
                 */
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                hdr.udp.length,

                /*
                 * Cabeçalho UDP
                 */
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length
            },

            hdr.udp.checksum,

            HashAlgorithm.csum16
        );
    }
}


/********************************************************************
 * DEPARSER
 ********************************************************************/

control MyDeparser(
    packet_out packet,
    in headers hdr
) {

    apply {

        packet.emit(hdr.ethernet);

        packet.emit(hdr.ipv4);

        packet.emit(hdr.tcp);

        packet.emit(hdr.udp);
    }
}


/********************************************************************
 * SWITCH
 ********************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

