# pcap de demostración — `data/pcap/demo/sesion_demo.pcap`

> **Tráfico sintético de laboratorio, generado por `scripts/lab/generar_trafico.py` con semilla fija;
> no es una captura de red real.**
> Combina un episodio de `scripts/lab/generar_trafico.py` (ARP spoofing) con uno de
> `scripts/lab/generar_clones.py` (clon de MAC), los dos con semilla fija. No se
> emitió nada por ninguna interfaz: todo se escribió directamente a archivo.

## Qué contiene

Un recorte de 150 s (≈ 2,5 min) de la salida de los generadores congelados, sin tocar un solo byte de
las tramas. Lo produce `scripts/generar_demo_pcap.py` y es determinista: dos ejecuciones dan el mismo
sha256.

| | Valor |
|---|---|
| Archivo | `data/pcap/demo/sesion_demo.pcap` (pcap clásico, Ethernet, microsegundos) |
| Tamaño | 4 293 057 bytes (4,29 MB) |
| sha256 | `3db1b93782256f7fab3cee27462129ec62ee8523983d81967fbc056454ec989b` |
| Tramas | 9 827 (8 853 del laboratorio + 974 del generador de clones) |
| Flujos (5-tupla TCP/UDP) | 1 640 |
| Tipos | TCP 8 185, ARP 821, DNS 469, ICMP 179, UDP 93, LLC/STP 75, LLDP 5 |
| Reloj | `t = 1 000 000 s + segundo de la sesión original` (reloj sintético del generador) |

Dos segmentos en el mismo archivo:

1. **Segmento 10.0.0.0/24, canal de ataques**: sesión de desarrollo 0 de `generar_trafico.py`
   (semilla 42 000), segundos 236–386. Trae fondo benigno de 27 MACs de origen (web, DNS, NTP, ICMP, ARP,
   VLAN 100, STP sobre 802.3/LLC, LLDP) y **un único episodio del catálogo**: `arp_spoofing`, variante `carrera_host`,
   intensidad `media`, segundos 276,4–331,1, atacante `a4:83:e7:99:34:f4`, 197 tramas de ataque
   (respuestas ARP `is-at` que reclaman 10.0.0.3, el servidor de archivos).
2. **Segmento 10.20.0.0/24, canal de identidad**: sesión 1 de `generar_clones.py` (semilla 77 001),
   segundos 234,6–384,6 desplazados +1,4 s para caer en la misma ventana. Trae 12 equipos con pilas
   distintas (TTL, ventana, opciones TCP, política de IP-ID) y **un episodio de clon de MAC** de nivel
   `ritmo`: el atacante usa la MAC y la IP de la víctima `02:2d:25:a4:7d:30` (10.20.0.24, pila IoT:
   TTL 255, ventana 5840, solo MSS) con pila Android (TTL 64, ventana 65535,
   `MSS,SAckOK,Timestamp,NOP,WScale`), segundos 306,0–378,5.

¿Por qué dos generadores? El generador congelado no fija el IP-ID (Scapy deja `id=1` en todas las
tramas) ni opciones TCP. Las señales de pila del canal de identidad (`src/identidad.py`) solo existen
en `generar_clones.py`, que es con el que se midió E3. Los segmentos no se mezclan: otra subred, otras
MACs y otro gateway. Hay una coincidencia: los dos generadores usan 93.184.216.34 como servidor
externo. Por eso el verificador agrupa el IP-ID por emisor (MAC, IP) y no solo por IP.

Archivos que acompañan al pcap, en el mismo directorio:

| Archivo | Para qué |
|---|---|
| `sesion_demo.tramas.csv` | Verdad terreno por trama del episodio del catálogo (la lee `pcap_to_features.py`) |
| `sesion_demo.episodios.csv` | El episodio del catálogo como intervalo |
| `sesion_demo.config.json` | Gateway y resolver declarados al IDS (segmento 10.0.0.0/24) |
| `sesion_demo.clones.json` | Equipos y episodio de clon (verdad terreno del canal de identidad) |
| `sesion_demo.meta.json` | Procedencia: generadores, semillas, ventanas, desfase, sha256 |

El clon **no** figura en `.tramas.csv`: es un ataque a la identidad, no del catálogo del modelo de
ataques. Por eso `pcap_to_features.py` etiqueta sus ventanas como benignas.

## Cómo abrirlo en Wireshark

```bash
wireshark data/pcap/demo/sesion_demo.pcap      # o: Archivo → Abrir
tshark -r data/pcap/demo/sesion_demo.pcap -c 20  # vista rápida en terminal
```

Conviene *View → Time Display Format → Seconds Since Beginning of Capture*: así el episodio ARP queda
entre ≈ 40 s y 95 s y el clon entre ≈ 70 s y 142 s de la captura.

Filtros de visualización que muestran la evidencia:

| Filtro | Qué se ve |
|---|---|
| `arp` | Las 821 tramas ARP (315 `who-has`, 506 `is-at`) |
| `arp.opcode == 2 && eth.src == a4:83:e7:99:34:f4` | Las respuestas ARP del atacante que reclaman 10.0.0.3 |
| `tcp.flags.syn == 1` | Arranques de conexión: TTL, ventana y opciones de cada pila |
| `tcp.flags.syn == 1 && eth.src == 02:2d:25:a4:7d:30` | La MAC clonada: SYN con TTL 255 y ventana 5840 (víctima) y, desde ≈ 70 s de captura, también con TTL 64 y ventana 65535 (clon) |
| `tcp.options` | Las 288 tramas TCP con opciones (todas del segmento 10.20.0.0/24) |
| `ip.id` (añadir como columna) / `ip.id != 1` | IP-ID: constante `1` en el segmento 10.0.0.0/24; contador, aleatorio o cero según la pila en 10.20.0.0/24 |
| `dns` | Consultas y respuestas: `dns.id` (txid) y `dns.qry.name` |
| `vlan` | Las 141 tramas 802.1Q (VLAN 100) |
| `stp` (o `llc`) | Las 75 BPDU STP: tramas IEEE 802.3 con campo longitud (38) y LLC DSAP/SSAP 0x42; alimentan `tasa_llc` |
| `lldp` | Anuncios LLDP del control de red (5) |

## Verificación con Scapy

```bash
.venv/bin/python scripts/verificar_demo_pcap.py
```

Imprime ejemplos con el valor real de cada campo (MAC origen y destino, OUI, ethertype, VLAN, IP
origen y destino, IP-ID, TTL, protocolo, puertos, ventana y opciones TCP, ARP op/hwsrc/psrc, DNS
txid/qname, LLC/STP). Después imprime los agregados por campo, las tramas del episodio de ataque y las dos
pilas vistas bajo la MAC clonada. Cierra con `9827 tramas, 1640 flujos, tipos: TCP 8185, ARP 821, DNS 469, ICMP 179, UDP 93, LLC/STP 75, LLDP 5`. Sale con código 1
si faltan ARP, TCP con opciones o algún cambio de IP-ID.

## Qué columna sale de cada campo

Esquema 3.0 (`src/feature_schema.py`), ventanas de 5 s por MAC de origen (`src/ventanas.py`):

| Campo en Wireshark | Columnas del esquema 3.0 (modelo de ataques) |
|---|---|
| `frame.len` | `n_tramas`, `bytes_totales`, `longitud_trama_media`, `longitud_trama_std`, `pct_menor_64`, `n_tramas_60s` |
| `frame.time_delta` (mismo origen) | `iat_media_ms`, `iat_std_ms` |
| `eth.src` | Clave de la fila (`mac`), `macs_nuevas_por_s`, `macs_activas`, `ratio_macs_una_trama` |
| `eth.dst` (bit I/G, broadcast) | `tasa_unicast`, `tasa_multicast`, `tasa_broadcast`, `macs_destino_distintas` |
| `eth.type` | `entropia_ethertype` |
| `vlan.id` | `tasa_vlan` |
| `llc` (802.3 con longitud) | `tasa_llc` |
| `arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.*` | `arp_requests`, `arp_replies`, `arp_replies_no_solicitadas`, `arp_gratuitos`, `arp_cambios_vinculo`, `arp_ether_distinto_hwsrc`, `arp_gateway_reclamado`, `arp_*_60s` |
| `tcp.flags.syn/ack/reset` | `n_syn`, `tasa_syn`, `syn_medio_abiertos`, `ratio_syn_medio_abiertos`, `n_rst`, `syn_medio_abiertos_60s`, `syn_sin_synack_max_destino`, `syn_medio_abiertos_max_destino` |
| `ip.src`, `ip.dst` | `ips_origen_distintas`, `ips_destino_distintas`, `ips_destino_distintas_60s` |
| `tcp.dstport` / `udp.dstport` | `puertos_destino_distintos`, `entropia_puertos_destino`, `conexiones_distintas`, `puertos_destino_distintos_60s` |
| `icmp.type` | `n_icmp_echo`, `respuestas_no_solicitadas` (echo reply sin request, error ICMP sin datagrama citado) |
| `dns.flags.response`, `dns.id`, `ip.src` del resolver | `dns_consultas`, `dns_respuestas`, `dns_respuestas_sin_consulta`, `dns_multiples_respuestas_txid`, `dns_resolver_no_autorizado`, `dns_respuestas_sin_consulta_60s` |
| ARP/DNS/ICMP respuesta sin petición en 5 s | `respuestas_no_solicitadas`, `tasa_respuestas_no_solicitadas`, `respuestas_no_solicitadas_60s` |

El OUI (`eth.src`, tres primeros octetos) se lee y se muestra, pero salió del modelo en el esquema
3.0: `OUI % 50` colisionaba y no es ordinal.

Señales de **identidad** (`src/identidad.py`, fuera del contrato de 52 columnas):

| Campo en Wireshark | Señal de identidad |
|---|---|
| `ip.ttl` | `ttl` (por valor distinto presente en la ventana) |
| `tcp.window_size_value` en SYN / SYN-ACK | `tcp_window` |
| `tcp.options` en SYN / SYN-ACK | `tcp_opciones` (firma: tupla de nombres de opción) |
| `ip.id` por flujo | `ipid_continuidad`, `ipid_salto_log2` |
| `tcp.seq` por flujo | `seq_continuidad` |
| `arp.src.*`, `ip.src` ↔ `eth.src` | vínculo IP→MAC del vigilante (E3, E4C) |

## Comprobado que el pipeline lo consume

```bash
.venv/bin/python scripts/pcap_to_features.py --pcap data/pcap/demo/sesion_demo.pcap --salida /tmp/demo_ventanas.csv
```

Produce 708 filas (ventana de 5 s × MAC de origen) sobre 30 ventanas de 5 s y 41 MACs, con las 65
columnas del dataset (52 de modelo + etiqueta + traza + identificación). 11 filas quedan etiquetadas
`arp_spoofing` (las del atacante con al menos K = 2 tramas de ataque) y 697 como `normal`.

## Replay offline en el motor de streaming (E5)

```bash
.venv/bin/python scripts/captura_en_vivo.py --pcap data/pcap/demo/sesion_demo.pcap \
    --dataset data/dataset_lab.csv --red-local 10.0.0.0/24
```

Con el corpus regenerado (`data/dataset_lab.csv`, sha256 `7f06d099…a945`), el motor entrena el
supervisado al arrancar (umbral 0,9086 a 1 FA/disp-día) y reproduce el pcap en 3,8 s: 9 827 tramas,
708 ventanas, 51 alarmas del supervisado (12 sobre el atacante ARP `a4:83:e7:99:34:f4`), 5 de
identidad (una sobre la MAC clonada `02:2d:25:a4:7d:30`) y 12 alertas del vigilante, con una latencia
media de 4,1 ms por ventana. **Esto es una demostración, no una medida de falsas alarmas**:

- son 150 s, menos de lo que el perfil de identidad necesita para salir de `no_confiable`;
- el archivo junta dos segmentos, así que las columnas de nivel de segmento (`macs_activas`,
  `macs_nuevas_por_s`, …) no se parecen a las del entrenamiento;
- de las 39 alarmas del supervisado que no caen sobre el atacante, 10 son del gateway del generador
  de clones (`02:00:00:00:00:01`) y 10 del resolver `b8:27:eb:2a:4f:6d`.

Las cifras de FA del proyecto son las de `reports/`.
