# Estado del proyecto IDS (IEEE 802.3)

> Dueño en esta ventana: PEDIDO-E3B-1. Actualizado el 2026-11-14, al cerrar E3B.
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
| E4–E6 | No empezadas | — | — |

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

## Restricciones que siguen en pie

- El holdout 20–29 está gastado: cualquier cifra «final» nueva necesita sesiones reservadas
  nuevas (≥ 30).
- Los generadores `generar_trafico.py` y `generar_dataset_lab.py` están congelados. Lo
  nuevo va en generadores propios: `generar_clones.py` (77000+), `generar_variacion.py`
  (78000+), `generar_suplantacion.py` (79000+), `generar_contaminacion.py` (80000+).
  Sesiones de E3 ya usadas: clones 0–39, variación 0–19, suplantación 0–39, contaminación 0–19.
- Sin `git push` desde estas ventanas.

## Pendiente para Nico

- Decidir el mensaje del artículo con los cinco resultados de arriba.
- Para E4 (laboratorio real): FA con variación real y DHCP real; los RST de la víctima frente
  a un clon de pila completa en un switch; juzgar los contadores de IP-ID **entre ventanas**;
  un mecanismo para aprender cambios legítimos sin aprender clones (registrado antes de medir
  y medido en sesiones nuevas); defensa para la fase `no_confiable`.
