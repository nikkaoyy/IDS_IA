---
name: generate-dataset
description: >-
  Guía para generar el dataset propio del IDS en un laboratorio virtual (Mininet/netns + Scapy),
  con tráfico benigno y ataques reales etiquetados por escenario y capa. Resuelve §3.1 opción A.
when_to_use: >-
  Use when the user asks to generate real data, create a dataset, set up a lab environment,
  capture real traffic, or implement option A/B/C from CONTEXT_UPGRADE.md §3.1.
allowed-tools: Bash, Read, Write, Edit
---

# Generar Dataset en Laboratorio Virtual

## Opciones de dataset (de CONTEXT_UPGRADE.md §3.1)

| Opción | Descripción | Pros | Contras |
|--------|------------|------|---------|
| **A (recomendada)** | Dataset propio en lab virtual (Mininet/netns + Scapy) | Tiene huella 802.3 real, alineado con "entornos simulados" | Más trabajo de setup |
| **B** | CICIDS para flujo + dataset propio para huella 802.3 | Usa "dataset de referencia" | Dos datasets, más complejo |
| **C** | Dataset existente con capa 2 (IoT Sentinel, CIC IoT 2023, o CICIDS pcaps crudos) | Menos trabajo | Puede no tener exactamente lo que necesita el proyecto |

## Opción A: Laboratorio virtual con Mininet

### 1. Instalar Mininet

```bash
sudo apt-get install mininet
# O con network namespaces si no se puede instalar Mininet
```

### 2. Crear topología de red

`scripts/lab/topologia.py`:
```python
"""Topología Mininet con N hosts, cada uno con MAC/OUI distintos."""
from mininet.net import Mininet
from mininet.topo import Topo
```

- Mínimo 5-10 dispositivos con OUI distintos (simular fabricantes)
- Switch OpenFlow para control
- Enlace entre hosts con delay simulado

### 3. Generar tráfico benigno

`scripts/lab/trafico_benigno.py`:
- HTTP (wget/curl entre hosts)
- DNS (consultas periódicas)
- ARP (resolución normal)
- ICMP (ping periódico)
- Variar ritmos por dispositivo (cada uno con su patrón temporal)

### 4. Generar ataques (por capa)

| Ataque | Capa | Herramienta | Script |
|--------|------|-------------|--------|
| ARP spoofing | Enlace (2) | arpspoof / Scapy | `scripts/lab/ataque_arp.py` |
| MAC spoofing/flooding | Enlace (2) | macchanger / Scapy | `scripts/lab/ataque_mac.py` |
| SYN flood | Transporte (4) | hping3 / Scapy | `scripts/lab/ataque_syn.py` |
| Port scan | Transporte (4) | nmap | `scripts/lab/ataque_portscan.py` |
| DNS spoofing | Aplicación (7) | ettercap / Scapy | `scripts/lab/ataque_dns.py` |

### 5. Capturar en pcap

```bash
# Captura simultánea mientras corren los escenarios
sudo tcpdump -i s1-eth1 -w data/escenario_benigno.pcap &
# Ejecutar tráfico benigno...
# Luego cada ataque en su propio pcap etiquetado
```

### 6. Convertir pcap a features

Crear `scripts/pcap_to_features.py`:
- Leer pcap con Scapy
- Agrupar tramas por MAC + ventana temporal (e.g., 5 segundos)
- Extraer features 802.3: estadísticos de longitud, IAT, tasa broadcast/ARP, entropía ethertypes
- Extraer features de flujo: tasa SYN, entropía puertos, conexiones/min
- Etiquetar: benigno (0) o malicioso (1), tipo de ataque, capa
- Guardar como CSV/Parquet en `data/dataset_lab.csv`

### 7. Validación del dataset

```python
import pandas as pd
df = pd.read_csv("data/dataset_lab.csv")
print(f"Total: {len(df)}, Clases: {df['etiqueta'].value_counts().to_dict()}")
print(f"Ataques: {df['tipo_ataque'].value_counts().to_dict()}")
print(f"Capas: {df['capa'].value_counts().to_dict()}")
assert df['etiqueta'].nunique() >= 2
assert len(df) >= 500  # Mínimo razonable
```
