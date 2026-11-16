# Trabalho 3 — Detecção e tratamento de fluxos elefante em P4

Anomalia escolhida: **fluxo elefante** (host que oferece volume acima de um limiar no enlace compartilhado).
Base: o NAT do Trabalho 2, inalterado, com o detector e o tratamento inseridos **antes** da tradução.

## Arquivos

| Arquivo | Onde vai | Papel |
|---|---|---|
| `basic.p4` | raiz do exercício | NAT do T2 + detector + duas estratégias (Passos 1–3) |
| `topology.json` | `pod-topo/` (substitui o do T2) | igual ao T2, com o enlace S1–H3 limitado a 10 Mbps |
| `s1-runtime.json` | `pod-topo/` | **sem alteração** (o detector não usa tabelas) |
| `anomalia_server.py` | raiz | servidor em H3: conta o que chega, ecoa sondas de RTT |
| `anomalia_client.py` | raiz | gerador de tráfego (UDP/TCP) e medidor de RTT em H1/H2 |
| `anomalia_ctl.py` | raiz | plano de controle: escolhe a estratégia, zera e lê os contadores do switch |
| `anomalia_report.py` | raiz | tabelas, CSV e gráficos comparando as execuções |
| `testes_t3.mn` | raiz | roteiro completo, equivalente ao `testes.txt` do T2 |

## Como executar

```
make clean && make run            # na raiz do exercício, com os arquivos acima copiados
mininet> source testes_t3.mn      # ~4 min; ao final, tabelas e gráficos em anom_obs/
```

Antes da primeira vez, confirme que o plano de controle alcança o switch: `mininet> sh python3 anomalia_ctl.py show`.
Se falhar, descubra a porta Thrift com `sudo ss -ltnp | grep simple_switch` e use `--thrift-port` (padrão 9090).

---

## Passo 1 — Definição e justificativa da anomalia (1,0)

**Definição.** Um host é *elefante* quando o volume que ele **oferece** ao switch passa de **50.000 bytes em uma janela de 100 ms** (4 Mbps).

**Justificativa.**
- O gargalo S1–H3 tem 10 Mbps = 125.000 bytes por janela de 100 ms. O limiar é **40% da capacidade**.
- Com uma fila FIFO compartilhada, um host acima de 40% já domina a fila: os pacotes dos demais passam a esperar atrás dos dele (aumenta o RTT) e, saturado o enlace, são descartados na mesma proporção.
- Mede-se o tráfego *oferecido* (inclusive o que será descartado). Assim o host só volta a ser tratado como normal quando **reduz a taxa que tenta enviar**, e não porque foi descartado.

Parâmetros (em `basic.p4`, constantes `DET_*`; o limiar também muda em tempo de execução com `anomalia_ctl.py thresh`):

| Parâmetro | Valor |
|---|---|
| Janela | 100 ms |
| Limiar | 50.000 bytes/janela (frame Ethernet visto no ingress) |
| Saída do estado (histerese) | 0,75 × limiar = 37.500 bytes/janela |
| Granularidade | por host (índice = último octeto do IP privado) |

## Passo 2 — Detector em P4 (2,5)

Roda no ingress, no ramo de **saída** do NAT (origem 10.0.0.0/24), antes da tradução; ali o IP de origem ainda é o privado e H1/H2 se distinguem. O tráfego de volta não é medido.

**Estado no data plane** (registradores de 256 posições, índice = último octeto do IP):

| Registrador | Conteúdo |
|---|---|
| `det_win_start`, `det_win_bytes` | início e bytes oferecidos na janela atual |
| `det_state`, `det_level` | 0 = normal / 1 = elefante; intensidade 1 a 3 |
| `det_first_seen`, `det_first_alarm`, `det_last_clear`, `det_alarms` | instrumentação: tempo de detecção e transições |
| `stat_pass_*`, `stat_drop_*` | pacotes e bytes encaminhados/descartados por host |
| `cfg_mode`, `cfg_thresh` | configuração (estratégia e limiar) |

**Algoritmo, a cada pacote:**
1. Soma o tamanho do pacote na janela. Se `bytes > limiar` dentro da janela, marca como elefante **na hora** (detecção antecipada, sem esperar a janela fechar).
2. Quando a janela de 100 ms termina, **reclassifica** com os bytes dela:
   - `> limiar` → elefante; nível 1, 2 ou 3 conforme a taxa seja `≤ 2×`, `≤ 3×` ou `> 3×` o limiar;
   - entre 0,75× e 1× o limiar → mantém o estado atual (evita oscilação);
   - `< 0,75×` o limiar → volta a normal.
3. Se a janela anterior ficou vazia (host parado por 2 janelas ou mais), conta como 0 bytes.

Isso cobre "atualizar a classificação conforme o tráfego evolui", inclusive o retorno ao normal.

## Passo 3 — Estratégias de tratamento (2,5)

O modo é escolhido em tempo de execução (`cfg_mode`), sem recompilar, o que garante comparar **sob condições idênticas**. A decisão só se aplica a host classificado como elefante; o descartado não passa pelo NAT nem pelo encaminhamento.

| Modo | Comando | Comportamento |
|---|---|---|
| `off` | `anomalia_ctl.py prepare --mode off` | **Sem mitigação** (linha de base): detecta e registra, mas encaminha tudo |
| `total` | `... --mode total` | **Estratégia A, descarte total**: todo pacote de host elefante é descartado |
| `prob` | `... --mode prob` | **Estratégia B, descarte probabilístico**: usa `random()` e descarta 25% (nível 1), 50% (nível 2) ou 75% (nível 3) |

A probabilidade da B acompanha a intensidade: para um host a taxa `R` acima do limiar `T`, o descarte ideal para trazê-lo de volta a `T` é `1 − T/R`. Os três níveis aproximam essa curva usando só comparações e deslocamentos (o P4 não tem divisão).

## Passo 4 — Experimentos e avaliação (3,0)

**Topologia:** a do T2 (H1 e H2 → S1 NAT → H3). Gargalo: enlace S1–H3 a 10 Mbps, 1 ms.
**Tráfego:** H1 é normal (UDP, 2 Mbps, 20 s). H2 sobe a 15 Mbps de 5 s a 15 s e volta a 2 Mbps de 15 s a 20 s. Todas as execuções usam o mesmo tempo, taxa e topologia; só muda o modo do switch.

| Run | Protocolo do H2 | Modo | Objetivo |
|---|---|---|---|
| 1 | UDP, 2 Mbps | total | **Cenário normal**: não pode haver alarme nem descarte |
| 2 | UDP, 15 Mbps | off | Anomalia **sem mitigação** |
| 3 | UDP, 15 Mbps | total | Estratégia A |
| 4 | UDP, 15 Mbps | prob | Estratégia B |
| 5–7 | TCP, máximo possível | off / total / prob | Mesmo experimento com elefante TCP (H1 segue UDP) |

**Métricas** (em `anomalia_report.py`, nas janelas antes / durante / depois da anomalia):
- **Throughput** recebido em H3 por host (Mbps).
- **Perda**: UDP por número de sequência, por host. Para TCP, retransmissões (`/proc/net/snmp`) e % descartado pelo switch.
- **RTT de H1**: média, p95, máximo e sondas perdidas (10 sondas/s por UDP, pois o NAT descarta ICMP e `ping` não funciona).
- **Tempo de detecção** de H2: `det_first_alarm − det_first_seen`, medido no switch.

Saídas: tabela no terminal, `anom_obs/resumo.csv`, `serie_run<N>.csv` e, com matplotlib, `vazao_por_execucao.png`, `rtt_h1.png`, `comparacao.png`.

### Comportamento esperado (previsão, não medição)

Uma simulação em Python da **lógica do detector** (sem fila, sem NAT, sem BMv2) indica:

| Modo | Detecção | H2 admitido na anomalia | Queda de H2 |
|---|---|---|---|
| off | 26,5 ms | ~15 Mbps (sobrecarrega o gargalo) | 0% |
| total | 26,5 ms | ~0 Mbps | ~94% |
| prob | 26,5 ms | ~3,8 Mbps (≈ limiar) | ~70% |

Nos três casos H1 nunca é marcado, H2 volta ao normal logo após reduzir a taxa (≈15,1 s), e no cenário normal não há alarme. As medições no Mininet é que valem para o relatório; esta tabela serve de referência para conferir se o switch se comporta como projetado.

O trade-off a discutir: o descarte total protege H1 ao máximo, mas pune H2 por inteiro e ainda o mantém bloqueado enquanto ele insistir na taxa alta; o probabilístico deixa H2 operar perto do limiar, com algum impacto residual em H1. O PDF deixa claro que uma estratégia não precisa superar a outra.

## Passo 5 — Organização e demonstração (1,0)

Roteiro de demonstração (cada trecho do `testes_t3.mn` tem um banner `### PASSO N ###`):
1. Passo 0: servidor em H3 e teste de fumaça.
2. Passo 1: cenário normal (sem alarme).
3. Passo 2: anomalia sem mitigação (H1 degradado).
4. Passo 3A e 3B: as duas estratégias, na mesma carga.
5. Passo 4: repetição com TCP.
6. Passo 5: relatório com tabelas e gráficos.

Execução manual de uma rodada:
```
sh python3 anomalia_ctl.py prepare --mode total
h1 python3 anomalia_client.py h1 --run 3 --label udp-total --proto udp --phase 0:20:2 --probe --duration 20 > /tmp/h1.txt 2>&1 &
h2 python3 anomalia_client.py h2 --run 3 --label udp-total --proto udp --phase 5:10:15 --phase 15:5:2
h1 sleep 5
sh python3 anomalia_ctl.py stats --run 3
```

## Observações e limitações

- **Não validado no BMv2.** `basic.p4` não foi compilado neste ambiente (sem `p4c`). Os scripts foram testados em loopback e o `anomalia_ctl.py` contra um `simple_switch_CLI` simulado. Compile primeiro e, se o `p4c` reclamar de algo, corrija antes de rodar.
- **Nomes dos registradores:** o controle usa `MyIngress.<nome>`. Se o seu `p4c` nomear diferente, ajuste `PREFIX` em `anomalia_ctl.py`.
- **Tempo de detecção:** pressupõe que o primeiro pacote de H2 na execução já é parte da anomalia (é o que o roteiro faz). `prepare` zera os contadores antes de cada rodada.
- **Fila do enlace:** o TCLink usa buffer padrão de 1000 pacotes, então sem mitigação o RTT de H1 sobe bastante sob congestionamento. Isso é esperado e ajuda a visualizar o efeito.
- **TCP:** com descarte total ou probabilístico o TCP recua, a taxa oferecida cai abaixo do limiar e H2 pode ser reclassificado como normal e voltar a acelerar. Essa oscilação é comportamento real do sistema e merece comentário no relatório.
- **Taxas:** as taxas dos clientes são de payload UDP (1200 B); na rede cada pacote ocupa ~1242 B (cerca de 3,5% a mais).
- **Sensibilidade:** `sh python3 anomalia_ctl.py prepare --mode total --thresh 30000` testa outro limiar sem recompilar.
