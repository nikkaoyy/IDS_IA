# Estado del proyecto IDS (IEEE 802.3)

> Dueño en esta ventana: cierre E4–E7. Actualizado el 2026-11-15; E4 consolidada.
> Cifras con IC al 95 %; el detalle de cada una está en su informe.

## Etapas

| Etapa / pedido | Estado | Informe | Cifra principal |
|---|---|---|---|
| E1 — dataset del laboratorio | Cerrada | `docs/INFORME_E1.md` | Puerta de separabilidad con 6 desviaciones declaradas (xfail estricto) |
| E2 — clasificador por episodio | Cerrada (holdout 20–29 **gastado**) | `docs/INFORME_E2.md` (+ addendum 3.0) | XGB, esquema 3.0: recall por episodio **0,894 [0,856, 0,936]** a 0,89 FA/disp-día |
| Extractor (esquema 3.0) | Cerrado | `docs/INFORME_EXTRACTOR.md` | LOAO sin capa 2: XGB **0,228 [0,168, 0,286]**, RF 0,068 |
| Anomalías (solo benigno) | Cerrado | `docs/INFORME_ANOMALIAS.md` | IF sin capa 2: **0,185 [0,132, 0,244]**; no sirve a este presupuesto |
| **E3A — identidad, niveles 1–2** | **Cerrada** | `docs/INFORME_E3A.md` | Detección ingenuo **0,975**, ritmo **1,000**; latencia 4,2 s / 10,0 s; **FA 16,2/disp-día** (IP-ID) |
| **E3B — pila completa, variación, contaminación** | **Cerrada** | `docs/INFORME_E3B.md` | IP-ID por flujo: FA **16,2 → 0,38**; con variación benigna **826 FA/disp-día**; pila completa **0,20** (0,325 en sesiones nuevas; 0/47 sin contador global); contaminación 20 %: absorción **0,80**, detección 0,83 |
| **E4R — robustez del detector** | **Cerrada** | `docs/INFORME_E4R.md` | Recall supervisado por intensidad: media **0,935**, suave **0,891**, ráfaga **0,824** (no baja de 0,5); **0 invisibles por construcción**; OR de canales **+0,053** a **+122 FA/disp-día** |
| **E4C — régimen invisible del ARP lento** | **Cerrada** | `docs/INFORME_E4C.md` | ARP a paso ≥ 5 s: supervisado **1,000 → 0,000** (invisible por construcción); el vigilante IP→MAC (ahora lee ARP) lo detecta **1,000** con **0,0 FA/disp-día** sobre variación benigna |
| **E4 — evasión a nivel de pcap (consolida E4R+E4C)** | **Cerrada** | `docs/INFORME_E4.md` | Floods: pierden efecto antes de evadir el etiquetado (recall ≥ 0,5). ARP lento: supervisado **1,000 → 0,000**, vigilante IP→MAC **1,000** a 0,0 FA. Imitación de huella a nivel de paquete: laboratorio real |
| **E5C — adoptar un cambio sin absorber un clon** | **Cerrada** | `docs/INFORME_E5C.md` | FA con variación **826 → 382/disp-día** (−54 %, IC sin solape, `no_confiable` igual); detección casi intacta (ritmo 1,000 → 0,975); `dos_pilas` casi no mejora (límite) |
| E5 — Streaming (captura→ventanas→modelo→alerta en vivo) | No empezada | — | — |
| E6 — Mitigación (`dry-run`) y pronóstico de alertas | No empezada | — | — |
| E7 — Cierre (notebook `.ipynb`, README, OE1) | No empezada | — | — |

## Defensas del perfil de identidad (tras la ablación de E3B)

- Se quedan: sin aprendizaje en alerta (compromiso: evita la absorción y causa las FA
  persistentes con variación) y `no_confiable`.
- Apagadas: tope diario (sin efecto medido), reperfilado (lava el clon).

## Contratos

- **Modelo de ataques:** 52 columnas, `VERSION_ESQUEMA = 3.0`, cerrado. Dataset de desarrollo
  de 20 sesiones, sha256 `7f06d099…a945`.
- **Identidad:** señales de pila en `Trama` (bloque 1 de E3A) y perfil en `src/identidad.py`,
  **fuera** del contrato de ataques. La regeneración con el parser extendido da el mismo
  sha256.

## Conclusiones vigentes para el artículo

1. El supervisado detecta el catálogo conocido (0,894), pero no transfiere a tipos nuevos
   (LOAO 0,228). Lo poco que transfiere viene de contadores de violación de protocolo, no de
   la huella 802.3.
2. Un detector entrenado solo con benigno no lo arregla: 0,185. Ve volumen, no violaciones;
   sus falsas alarmas se concentran en uno o dos equipos.
3. El perfil de pila detecta clones con una pila distinta de la de la víctima (niveles 1–2)
   en segundos, a 0,38 FA/disp-día con el IP-ID juzgado por flujo (E3B). El vínculo IP→MAC
   detecta la víctima apagada (1,00) y la suplantación de IP (0,95).
4. **El sistema se rompe en el tercer nivel:** el clon de pila completa se detecta en el 20 %
   de los episodios, solo por el contador de IP-ID de víctimas Windows/IoT; con Linux, macOS o
   Android, 0 de 47.
5. **Con variación benigna realista** (actualizaciones, VPN, dos pilas, descubrimiento) las FA
   suben a 826/disp-día sin que `no_confiable` las esconda (0,128 de las ventanas), y un clon
   presente durante el aprendizaje es absorbido (0,80 al 20 %), con la dueña legítima acusada
   después. Las cifras de FA de los niveles 1–2 son optimistas por este factor.
6. **Robustez (E4R):** sobre el corpus congelado, el supervisado no baja de 0,5 de recall a
   ninguna intensidad (ráfaga 0,824, suave 0,891, media 0,935; curva **no monótona** porque
   `suave` dura más y deja más ventanas etiquetables) y **ningún episodio es invisible por
   construcción**. El OR con los canales de identidad sube el recall solo **+0,053** y a cambio
   de **+122 FA/disp-día** (826 con variación benigna): no compensa frente a floods ni escaneos.
7. **Régimen invisible (E4C):** el ARP spoofing se detecta con el clasificador por ventana solo
   mientras es rápido (recall 1,000 nativo). Separando sus tramas **5 s** —el tamaño de la ventana,
   muy por debajo del suelo de efecto de 60 s del `gc_stale`— ninguna ventana alcanza K=2 y el ataque
   es **invisible por construcción** para el supervisado (0,000), sin dejar de ser un ataque. El
   **vigilante IP→MAC**, extendido para leer el ARP (y corregida su red local, antes era la del lab de
   identidad), lo detecta al **1,000** en los pasos 5/15/30/60 s con **0,0 FA/disp-día** sobre la
   variación benigna de E3B. La defensa contra el ataque lento no es un mejor clasificador de volumen,
   sino una señal de identidad que no depende de la tasa.
8. **Tercera vía de aprendizaje (E5C):** adoptar un valor de pila nuevo solo cuando persiste de
   forma **exclusiva** (el equipo deja de usar el viejo) y eximir los que ya mostraba al construir el
   perfil baja las FA con variación benigna de **826 a 382/disp-día** (−54 %, IC sin solape, sin
   apagarse en `no_confiable`) sin perder la detección de clones de pila distinta (ingenuo 0,975,
   ritmo 0,975, pila completa 0,20). Precio: un clon de ritmo de 40 se absorbe si la víctima calla
   30 s. La mitad de la FA que queda es de un equipo con **dos pilas concurrentes**, indistinguible
   de un clon a nivel de huella: el límite de fondo del canal de identidad.

## Restricciones que siguen en pie

- El holdout 20–29 está gastado: cualquier cifra «final» nueva necesita sesiones reservadas
  nuevas (≥ 30).
- Los generadores `generar_trafico.py` y `generar_dataset_lab.py` están congelados. Lo
  nuevo va en generadores propios: `generar_clones.py` (77000+), `generar_variacion.py`
  (78000+), `generar_suplantacion.py` (79000+), `generar_contaminacion.py` (80000+).
  Sesiones de E3 ya usadas: clones 0–39, variación 0–19, suplantación 0–39, contaminación 0–19.
- Sin `git push` desde estas ventanas.

## Pendiente para Nico

- Decidir el mensaje del artículo con los ocho resultados de arriba.
- Para E6 (laboratorio real y ambigüedad de fondo): discriminar `dos_pilas` de un clon por el
  **lapso** de aparición (una pila legítima sale salpicada toda la sesión; un clon es una racha
  contigua tardía), registrado antes de medir y en sesiones nuevas; acotar la regresión de ritmo de
  E5C; y lo del laboratorio real: FA del vigilante con **DHCP y failover reales** (su 0,0 es optimista
  porque el lab no los tiene); los RST de la víctima frente a un clon de pila completa en un switch;
  juzgar los contadores de IP-ID **entre ventanas**; un mecanismo para aprender cambios legítimos sin
  aprender clones (registrado antes de medir y medido en sesiones nuevas); defensa para la fase
  `no_confiable`; y el DNS lento por carrera, que aquí solo se midió en tiempo nativo.
