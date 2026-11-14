# Estado del proyecto IDS (IEEE 802.3)

> Dueño en esta ventana: PEDIDO-E3A-1. Actualizado el 2026-11-14, al cerrar E3A.
> Cifras con IC al 95 %; el detalle de cada una está en su informe.

## Etapas

| Etapa / pedido | Estado | Informe | Cifra principal |
|---|---|---|---|
| E1 — dataset del laboratorio | Cerrada | `docs/INFORME_E1.md` | Puerta de separabilidad con 6 desviaciones declaradas (xfail estricto) |
| E2 — clasificador por episodio | Cerrada (holdout 20–29 **gastado**) | `docs/INFORME_E2.md` (+ addendum 3.0) | XGB, esquema 3.0: recall por episodio **0,894 [0,856, 0,936]** a 0,89 FA/disp-día |
| Extractor (esquema 3.0) | Cerrado | `docs/INFORME_EXTRACTOR.md` | LOAO sin capa 2: XGB **0,228 [0,168, 0,286]**, RF 0,068 |
| Anomalías (solo benigno) | Cerrado | `docs/INFORME_ANOMALIAS.md` | IF sin capa 2: **0,185 [0,132, 0,244]**; no sirve a este presupuesto |
| **E3A — identidad, niveles 1–2** | **Cerrada** | `docs/INFORME_E3A.md` | Detección ingenuo **0,975**, ritmo **1,000**; latencia 4,2 s / 10,0 s; **FA 16,2/disp-día** (IP-ID) |
| E3B — clon de pila completa, contaminación, víctima apagada, deriva | Pendiente | — | — |
| E4–E6 | No empezadas | — | — |

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
   en segundos, pero con la configuración registrada da 16 FA/disp-día por una señal de
   IP-ID mal diseñada. El caso que importa, el clon de pila completa, sigue sin medir.

## Restricciones que siguen en pie

- El holdout 20–29 está gastado: cualquier cifra «final» nueva necesita sesiones reservadas
  nuevas (≥ 30).
- Los generadores `generar_trafico.py` y `generar_dataset_lab.py` están congelados. Lo
  nuevo va en generadores propios (por ejemplo, `generar_clones.py`).
- Sin `git push` desde estas ventanas.

## Pendiente para Nico

- Decidir el mensaje del artículo con los cuatro resultados de arriba.
- Encargar E3B: clon de pila completa (con la señal de IP-ID rediseñada antes de medir),
  contaminación del perfil, víctima apagada y variación legítima de pila en el generador.
