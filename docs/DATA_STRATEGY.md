# Decisión de Estrategia de Datos (Fase 0 — §3.1)

> **Fecha de decisión:** 2026-10-21  
> **Autor:** Nicolás Martínez Pineda  
> **Estrategia seleccionada:** **Opción A (Laboratorio Virtual / Tráfico Propio)**

---

## 1. Análisis de Alternativas

| Opción | Descripción | Ventajas | Desventajas | Decisión |
|---|---|---|---|---|
| **A: Laboratorio Virtual (Mininet / Netns + Scapy)** | Generar tráfico benigno y vectores de ataque en un entorno de red controlado con dispositivos de OUI y patrones conocidos. | • Huella IEEE 802.3 real y controlada.<br>• Mapeo 1:1 con los objetivos OE1, OE2 y OE3.<br>• Permite probar suplantación de MAC/OUI real.<br>• Cero fugas y etiquetado perfecto por escenario. | Requiere configurar topología y scripts de inyección. | **SELECCIONADA** |
| **B: Enfoque Híbrido (CICIDS + Huella Propia)** | Usar CICIDS2017 para capa 3-4 y un dataset complementario para capa 2. | Aprovecha un dataset de referencia conocido en la academia. | • Desacople temporal complejo.<br>• Unir dos fuentes artificialmente genera inconsistencias.<br>• Mucho retrabajo de alineación. | Descartada |
| **C: Dataset Público con Capa 2 (IoT Sentinel, CIC IoT 2023, PCAPs CICIDS)** | Usar PCAPs sin procesar de CICIDS2017 o datasets IoT. | Datos de tráfico preexistentes. | • CICIDS2017 crudo pesa >50 GB.<br>• Los entornos IoT no representan topologías de campus/LAN corporativa 802.3.<br>• Tiempo de descarga y parsing prohibitivo. | Descartada |

---

## 2. Justificación Técnica de la Opción A

1. **Alineación con el objetivo general:**
   El proyecto plantea *"identificar en tiempo real la huella digital de dispositivos conectados vía IEEE 802.3"*. CICIDS2017 fue generado con `CICFlowMeter`, el cual descarta encabezados de enlace (MAC, EtherType, longitud de trama 802.3 vs. Ethernet II). Entrenar sobre CICIDS2017 puro ignora por completo la huella física y temporal de nivel 2.

2. **Factibilidad técnica y consumo de recursos:**
   - La opción de descargar PCAPs crudos de CICIDS2017 demandaría ~50 GB de almacenamiento y horas de procesamiento.
   - Un entorno virtual con Network Namespaces (`ip netns`) o `Mininet` junto a generadores basados en `Scapy` permite generar cientos de miles de tramas en minutos con un consumo de disco < 200 MB.

3. **Demostración rigurosa del valor de la Huella IEEE 802.3 (Ablación):**
   Con la Opción A, podemos entrenar:
   - Modelo con características de Flujo (Capa 3-4) únicamente.
   - Modelo con características de Huella IEEE 802.3 únicamente.
   - Modelo híbrido (Huella + Flujo).
   Esto demuestra empíricamente si la huella aporta poder discriminatorio frente a evasiones y suplantaciones de identidad.

---

## 3. Hoja de Ruta de Implementación de Datos

1. **Fase 0 (Actual):** Definir contrato formal de características (`src/feature_schema.py`) para que la captura, el dataset y el modelo compartan el mismo formato.
2. **Fase 1:** Scripts de laboratorio (`scripts/lab/`) para generar PCAPs etiquetados y convertirlos a Parquet/CSV (`scripts/pcap_to_features.py`).
