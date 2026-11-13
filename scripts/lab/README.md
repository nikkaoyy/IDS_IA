# Laboratorio virtual — generación del dataset (Fase 1, §3.1 opción A)

Este directorio construye el conjunto de datos etiquetado con el que se entrenan y
evalúan los modelos del IDS. Implementa la **opción A** decidida en
[`docs/DATA_STRATEGY.md`](../../docs/DATA_STRATEGY.md): tráfico propio con huella
IEEE 802.3 real, etiquetado por escenario y por capa del modelo TCP/IP.

## Enfoque por defecto: síntesis reproducible a PCAP (sin root)

`generar_trafico.py` **sintetiza con Scapy los patrones de tráfico representativos**
de cada escenario y los escribe directamente a archivos `.pcap`. No inyecta tráfico en
ninguna interfaz real: todo queda en archivos locales, es determinista (semilla fija) y
no requiere privilegios. El propósito es construir datos para entrenar un IDS
**defensivo** (OE1–OE3), no operar herramientas de ataque.

```bash
# Dataset completo: 20 sesiones de 15 min (timeline continuo, un pcap por sesión)
python scripts/lab/generar_dataset_lab.py --salida data/dataset_lab.csv

# Convertir sesiones ya generadas (lee .tramas.csv y .config.json junto al pcap)
python scripts/pcap_to_features.py --pcap data/pcap/sesion_000.pcap --salida d.csv

# Baseline de reglas por ataque
python scripts/baseline_reglas.py
```

## Escenarios y capas (OE1)

| Escenario | Capa TCP/IP | Huella característica |
|---|---|---|
| `benigno` | — | Handshakes TCP completos, DNS/ICMP/ARP con ritmo propio por dispositivo |
| `arp_spoofing` | Enlace (2) | Respuestas ARP `is-at` no solicitadas, alta tasa ARP desde una MAC |
| `mac_flooding` | Enlace (2) | Cardinalidad explosiva de MAC/OUI anunciadas (desborde de tabla CAM) |
| `syn_flood` | Transporte (4) | `tasa_syn`≈1, IAT mínimo, puerto único (baja entropía de puertos) |
| `port_scan` | Transporte (4) | Alta entropía de puertos destino desde un mismo origen |
| `dns_spoofing` | Aplicación (7) | Respuestas DNS forjadas (UDP/53) no solicitadas |

Cada ataque se genera en **episodios separados en el tiempo** (`ESPACIADO_EPISODIO_S`),
de modo que produzca muchas ventanas (muestras) y las clases queden balanceadas para la
validación cruzada por grupos de la Fase 3.

## Ventanas temporales y anti-fuga

`pcap_to_features.py` agrupa las tramas por `(MAC de origen, ventana de 5 s)`. Cada
grupo produce una fila con:
- la huella IEEE 802.3 (capa 2): estadísticos de longitud e IAT, tasa broadcast/ARP,
  entropía de EtherType, OUI codificado;
- las características de flujo (capas 3-4): `tasa_syn`, entropía de puertos destino,
  conexiones por minuto.

La columna `grupo = MAC#ventana` identifica la unidad de agregación y se usa como clave
en `StratifiedGroupKFold` para **evitar fuga temporal** entre entrenamiento y prueba.

## Alternativa: captura en vivo con Network Namespaces (requiere root)

Para quien disponga del laboratorio físico/virtual y quiera capturar tráfico real en
lugar de sintetizarlo, el flujo equivalente con `ip netns` es:

```bash
# Crear namespaces aislados (dispositivos virtuales) y un bridge:
sudo ip netns add disp1 && sudo ip netns add disp2
# ... configurar veth pairs contra un bridge, asignar IP/MAC por dispositivo ...

# Capturar mientras se genera tráfico dentro de los namespaces:
sudo ip netns exec disp1 tcpdump -i veth1 -w data/benigno.pcap

# Convertir la captura a features con el mismo parser:
python scripts/pcap_to_features.py --pcap data/benigno.pcap --etiqueta 0 ...
```

El resto del pipeline (features → modelos → evaluación) es idéntico: el parser consume
cualquier `.pcap` con tramas Ethernet, sintético o capturado en vivo.
