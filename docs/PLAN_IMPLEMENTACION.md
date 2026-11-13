# Plan de implementación — IDS funcional de extremo a extremo

Estado: revisado por ciberseguridad (aprobado con cambios, ya incorporados).
Fecha: 2026-10-31.

## Definición de "funciona"

Un pcap reproducido como flujo pasa por: huella por ventana -> modelo persistido -> alerta ->
mitigación simulada -> pronóstico. Los mismos extractores sirven a entrenamiento e inferencia, y
las métricas se reportan sin fuga y con intervalos de confianza, incluso si salen peor que 1.0.

Alcance: lab sintético en archivos pcap; sin inyectar tráfico en interfaces reales. El bloqueo
real (ebtables/iptables) queda solo como dry-run que imprime el comando; ejecutarlo requiere una
decisión explícita posterior del usuario.

## Bloqueos actuales

| # | Problema | Evidencia |
|---|---|---|
| B1 | Cada ataque es casi constante; clases trivialmente separables | `longitud_trama` 109 en DNS, `tasa_syn` 1.0 en SYN flood y port scan |
| B2 | Benigno irreal: 4 dispositivos, un OUI, la misma MAC emite SYN, SYN-ACK y ACK | `gen_benigno` |
| B3 | Ataques en MACs nuevas de 1 ventana; el benigno son 4 MACs de vida larga | 300 MACs por ataque, ~1.2 filas por MAC |
| B4 | Inferencia en vivo por trama con flujo por defecto; entrenamiento por ventana | `inferir`, `a_vector_modelo` |
| B5 | Extracción de ventana solo en `scripts/pcap_to_features.py`; nada en `src/` | no reutilizable en vivo |
| B6 | Sin streaming, mitigación, identidad de dispositivo, diagnóstico ni pronóstico | `capture.py`, `pipeline.py` |
| B7 | `oui_frecuente` es `OUI % 50`: colisiona y no es ordinal | `_oui_a_entero` |
| B8 | `grupo` es único por fila; el informe de Fase 1 lo presenta como anti-fuga | sección 4.3 |

## Etapas (revisadas tras la auditoría de ciberseguridad)

Cada etapa cierra con tests verdes y su criterio de salida. Las métricas sin mención de prevalencia
se reportan además a prevalencia fija de ventanas maliciosas de 1 % y 0.1 %.

Punto de observación declarado: SPAN/mirror de un segmento que ve todo el unicast. Ataques externos
enrutados llegan con la MAC del gateway y quedan fuera de la atribución por MAC.

### E0 — Núcleo de extracción único (B4, B5)
1. `src/ventanas.py`: agregador incremental usado por `pcap_to_features.py` y por vivo, con dos
   niveles: por `(MAC, ventana)` y global por segmento/destino. Ventana corta de 5 s y larga de 60 s
   o solapada para bajo y lento.
2. Esquema final en `feature_schema.py`:
   - ARP: conteo por `op`, réplicas no solicitadas, cambios de vínculo IP->MAC, `Ether.src` != `hwsrc`,
     gateway reclamado por otra MAC.
   - TCP: SYN medio abiertos en conteo absoluto y ratio, RST, IPs de origen por MAC.
   - DNS: respuestas sin consulta pendiente, múltiples respuestas por txid, resolver no autorizado.
   - Capa 2: `n_tramas`, bytes, unicast/multicast/broadcast, MACs destino, % < 64 bytes, VLAN, LLC.
   - Global: MACs nuevas/s, cardinalidad, ratio de MACs de una trama, SYN sin SYN-ACK por destino.
   - IAT/std son NaN sin datos. `oui_frecuente` y `oui_encoded` salen del modelo.
3. `inferir_ventana()` con artefacto validado; sin defaults de flujo; `pipeline.py` sin
   `logging.basicConfig` en importación. Test de paridad lote/incremental.

### E1 — Timeline de laboratorio con verdad terreno (B1, B2, B3, B7, B8)
1. Capturas continuas multi-escenario por sesión: mismo reloj, topología y fondo; ataques en instantes
   Poisson y duración variable; semilla distinta por sesión. Sustituye el pcap por clase.
2. Manifiesto por trama/intervalo (`atacante`, `episodio`, `tipo`, `capa`). Etiqueta de ventana: maliciosa
   si tiene al menos K tramas de ataque, K fijado antes de ver resultados.
3. Benigno: >= 20 dispositivos con perfiles y proceso temporal propio; flujos bidireccionales coherentes
   (`sport`, seq/ack, datos, FIN; timestamps distintos); DNS query/response; ARP request/reply; gratuitous
   ARP; ráfagas legítimas; escaneo administrativo; LLC/STP, LLDP, multicast, DHCP, 802.1Q; padding a 60
   bytes en TODO el tráfico.
4. Ataques: MAC flooding con `Ether.src` aleatorio por trama; ARP unicast lento y a ráfaga; DNS a la MAC
   de la víctima compitiendo con la respuesta real; SYN flood con MAC fija y rotatoria; intensidad variable;
   atacantes que reutilizan MACs; clones que coexisten con la víctima. Añadir un vector de red (ICMP flood).
5. Test de coherencia de flujos. Baseline de reglas (stump y árbol de profundidad 2) reportado por ataque
   como referencia, no como puerta de calidad.

### E2 — Evaluación del clasificador (OE2, OE3)
1. `src/evaluacion.py`: agrupar por sesión, con benigno por dispositivo y ataque por episodio/atacante;
   estratificar por `tipo_ataque`. Holdout final de sesiones de semilla no usada, abierto una sola vez.
2. IC por bootstrap sobre sesiones/episodios. Leave-one-attack-out. Ablación capa 2 / capas 3-4 / completo.
3. Umbral en validación anidada para un FPR objetivo numérico; falsas alarmas por dispositivo/día;
   recall por episodio y tiempo hasta detección.
4. RF vs. XGBoost: PR-AUC, FPR en umbral, recall por ataque y métricas exigidas por OE3. Multiclase por
   tipo y capa. Importancia por permutación. Reporte JSON con Markdown derivado en `reports/`.

### E3 — Identidad (B6, OE2)
`src/identidad.py`, con split temporal por dispositivo. Señales: TTL, ventana y opciones TCP, continuidad
de IP-ID y seq, conflictos de sesión. Tres niveles de clon (ingenuo, imita ritmo y tamaños, imita pila);
caso con víctima apagada. Baseline mediana/MAD, mínimo de ventanas, estado `no_confiable`, sin aprendizaje
durante alertas, actualización limitada. Pruebas con 5 % y 20 % de contaminación y deriva lenta. Se declara
que un clon de pila completa y un atacante presente en todo el aprendizaje no se resuelven.

### E4 — Evasión a nivel de pcap (OE3)
Reemplaza `simular_evasion`. El pcap perturbado pasa por `ventanas.py` contra el sistema completo. Invariantes
de efecto: medio abiertas/s, refresco ARP menor que caché, inserciones CAM/s, puertos por hora, DNS antes de
la respuesta real. Curva recall vs. intensidad con dilución, bajo y lento, reparto entre ventanas y rotación
de MAC. Donantes de una sesión de observación propia. Una ronda de reentrenamiento adversarial (recortable).

### E5 — Streaming
`src/streaming.py`: `AsyncSniffer` -> contadores agregados -> cola acotada -> inferencia, con fuente pcap sin
root. Cuotas de estado separadas (confiables protegidos, MACs nuevas en tabla pequeña); saturación como alerta.
Prueba de inundación a pps creciente: memoria, p95 (objetivo < 50 ms por ventana), descartes, pps máximo y
recall bajo descarte.

### E6 — Mitigación y pronóstico (OE3)
`src/mitigacion.py`: alerta / propuesta de bloqueo / bloqueo simulado. Conflicto de identidad o alerta global
nunca bloquea MAC automáticamente. Excluido no significa invisible: alerta crítica. Tope de bloqueos por minuto
y TTL con backoff. Backend solo imprime comandos. Se evalúa reproduciendo el timeline: tramas de ataque suprimidas,
legítimas perdidas y víctimas bloqueadas por el atacante. `src/pronostico.py`: Holt-Winters vs. ingenuo con backtesting.

### E7 — Cierre
`make data train eval live`, README, informe OE1, corrección de la sección 4.3 de `docs/INFORME_FASE_1.md`,
CLAUDE.md y versiones fijadas.

## Riesgos

- Sigue siendo sintético: los resultados valen para este lab; se declara explícitamente.
- Decisión cerrada: el docente no exige CICIDS. El dataset del proyecto es el laboratorio propio.
- Sesgo del autor: los parámetros del generador deciden la dificultad. Se fijan antes de ver
  resultados y se documenta cualquier ajuste posterior.

## Flujo de trabajo

Plan -> revisión de ciberseguridad -> codificación -> revisión de código -> aprobación final, por incrementos.
Primer incremento: E0 + E1.
