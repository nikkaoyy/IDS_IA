SEGUIR — E3A bloques 1 y 2 hechos; sigue el bloque 3 (generar_clones.py + evaluar_identidad.py ya escritos: correr, informe, ESTADO.md).

# Progreso — PEDIDO-ANOMALIAS-1 y después PEDIDO-E3A-1

Bitácora del bucle (`/loop` autodirigido). La primera línea es el semáforo: `SEGUIR` con el
siguiente paso, o `PARAR` con el motivo. Orden: anomalías bloques 1→3, después E3A bloques 1→3.

## Decisiones registradas antes de ver ninguna cifra (anomalías)

- Ajuste solo con `benignas_limpias` de las sesiones de train; la etiqueta no llega al
  modelo (`EtiquetaEnAjusteError` si se pasa la columna).
- Umbral: `umbral_para_objetivo` sobre los puntajes benignos limpios fuera de fold de 3 folds
  internos por sesión. Se calcula con un DataFrame que solo contiene filas benignas limpias,
  así que el dispositivo-día interno se mide sobre el lapso benigno de cada (sesión, MAC).
- Hiperparámetros por defecto o fijados a priori: IF de 200 árboles; LOF con 20 vecinos,
  `novelty=True` y una submuestra de 20 000 filas benignas (por coste); PCA del 95 % de la
  varianza benigna + el mismo IF. NaN → 0 tras escalar.
- Semillas 42–46 y 5 folds, las mismas que E2, para que la comparación con 0,894 sea con el
  mismo reparto.
- Autoencoder: fuera (sin `torch` en el entorno; el pedido lo deja como opcional).
- **Limitación declarada antes de medir:** IF sobre PCA no ve una anomalía que solo se sale
  del rango por el primer componente. El IF satura fuera del rango de entrenamiento y en el
  resto de componentes el punto cae en el centro benigno (caso sintético: 0,46 frente a un
  máximo benigno de 0,62). Figura como xfail estricto en `tests/test_anomalias.py`.
- **Desviación de forma:** la configuración lleva `conjuntos: [sin_capa2, completo]` (lista)
  en vez de un solo `conjunto`, para que una corrida deje los dos en `reports/anomalias.json`
  con claves `modelo/conjunto`. `sin_capa2` es el principal.

## Registro

| Paso | Qué | Commit |
|---|---|---|
| A1 | `src/anomalias.py`, `scripts/evaluar_anomalias.py`, `configs/anomalias.json`, `tests/test_anomalias.py` (12 passed + 1 xfail). Ensayo de tiempos: ≈ 25 s por semilla y modelo | ver `git log` |
| A2 | Evaluación completa: `reports/anomalias.json` / `.md` (5 semillas × 5 folds × 3 modelos × 2 conjuntos, ≈ 14 min) | ver `git log` |

## Bloque 2 — cifras (sin reajustar nada después de verlas)

Recall por episodio a ≤ 1 FA/dispositivo-día (objetivo), IC 95 %:

| Modelo / conjunto | Recall episodio | FA/disp-día medidas | PR-AUC ventana | Folds con FA de test > 1 |
|---|---|---|---|---|
| **isolation_forest/sin_capa2** (principal) | **0,185 [0,132, 0,244]** | 1,16 [0,21, 2,29] | 0,304 | 10/25 |
| lof/sin_capa2 | 0,132 [0,087, 0,181] | 1,16 [0,00, 2,84] | 0,451 | 5/25 |
| isolation_forest_pca/sin_capa2 | 0,133 [0,093, 0,177] | 1,28 [0,18, 2,83] | 0,286 | 11/25 |
| isolation_forest/completo | 0,170 [0,119, 0,227] | 1,28 [0,47, 2,38] | 0,238 | 9/25 |
| lof/completo | 0,113 [0,070, 0,156] | 0,83 [0,00, 2,08] | 0,439 | 5/25 |
| isolation_forest_pca/completo | 0,168 [0,119, 0,220] | 0,51 [0,00, 1,26] | 0,247 | 5/25 |

**Diagnóstico estructural (medido después, sin cambiar nada):** 9 de las 38 columnas de
`sin_capa2` son constantes o casi en el benigno limpio. Entre ellas, los cinco contadores de
violación exactos (`respuestas_no_solicitadas`, su tasa, `arp_replies_no_solicitadas`,
`arp_ether_distinto_hwsrc`, `dns_respuestas_sin_consulta`) valen 0 en el 100 % de las 72 523
ventanas benignas limpias. Un IsolationForest no puede partir por una columna constante en
su submuestra de 256 filas, así que **los contadores que mejor delatan un ataque son
invisibles para el IF**: icmp_flood 0,000 y arp_spoofing 0,024. LOF mide distancias y sí los
ve (icmp_flood 0,335, arp_spoofing 0,218), pero pierde mac_flooding (0,029, frente a 0,559
del IF).

**Deriva:** ninguna MAC legítima aparece en más de una sesión (el generador crea los equipos
por sesión), así que no se puede medir si el detector castiga al mismo equipo día tras día.
Sí se ve concentración dentro de la sesión: con LOF el 100 % de las falsas alarmas cae en 2
de 854 dispositivos, y `3c:52:82:cb:0c:43` es el más castigado en 4 de las 6 corridas.
| A3 | `docs/INFORME_ANOMALIAS.md`: comparación, deriva, por ataque y respuesta (no sirve a este presupuesto: 0,185 frente a 0,228 LOAO y 0,894) | ver `git log` |

### Cierre de PEDIDO-ANOMALIAS-1

- Gana IsolationForest sobre sin_capa2: recall por episodio 0,185 [0,132, 0,244] a 1,16 FA/disp-día (los IC de todos los modelos se solapan).
- Frente al supervisado: 0,894 con el tipo en el entrenamiento y 0,228 en LOAO (IC solapado con 0,185); detecta ráfagas (0,476) y mac_flooding (0,559), pierde icmp_flood (0,000) y arp_spoofing (0,024).
- Peor deriva: IF, `a4:83:e7:cf:70:df`, 1,4 FA en 15 min ≈ 135 FA/disp-día (18 % del total); con LOF, el 100 % de las FA en 2 de 854 equipos (peor: 435/día).
- Para Nico: decidir si el artículo menciona el contraste; cualquier combinación (IF+LOF, regla de contador) exige sesiones nuevas; la deriva entre días necesita equipos persistentes.

## PEDIDO-E3A-1

| Paso | Qué | Commit |
|---|---|---|
| E1 | `Trama` gana `ip_ttl`, `ip_id`, `ip_df`, `tcp_window`, `tcp_options`, `tcp_seq`, `tcp_ack`; `trama_desde_paquete` los rellena; el agregado no los lee. Dataset regenerado con el parser extendido: **sha256 `7f06d099…a945`, idéntico** | ver `git log` |

Notas del bloque 1:
- Los `EOL` finales de las opciones TCP se descartan: son relleno de alineación, no una
  elección de la pila.
- El criterio se corrió con la salida en `$CLAUDE_JOB_DIR/tmp` en vez de `/tmp` (varios
  trabajos comparten `/tmp`). Mismo comando y mismo resultado.
- En el pcap congelado, el IP-ID vale 1 en todas las tramas IP (el valor por defecto de
  Scapy), no hay opciones TCP y el SEQ del SYN también es por defecto en muchos casos. Solo
  el TTL (64/128/255) y la ventana del SYN (8192/29200/64240) llevan información. Por eso el
  bloque 3 necesita su propio generador.
| E2 | `src/identidad.py`: perfil por mediana/MAD, `MIN_VENTANAS_PERFIL = 12`, sin aprendizaje durante alertas, tope diario; `tests/test_identidad.py` (16 passed). Criterio: `test_ventanas.py` + `test_identidad.py` 36 passed | ver `git log` |

Decisiones del bloque 2, fijadas antes de ver ningún clon:
- `MIN_VENTANAS_PERFIL = 12` ventanas con señal de pila (un minuto de actividad). Con n = 12
  la mediana aguanta 5 ventanas raras, y coincide con la ventana larga de 60 s del extractor.
- Puntaje = máximo de |x − mediana| / max(1,4826·MAD, piso, 1 % de la mediana) entre señales
  presentes; firma de opciones nueva = 10; alarma si > 6.
- **TTL y ventana TCP se juzgan por valor distinto en la ventana**, no por su mediana: el clon
  comparte MAC y ventana con la víctima, y una mediana lo escondería si es minoritario. Un
  valor visto en ≥ 2 ventanas del perfil no cuenta (así se aprende el TTL 255 del mDNS).
  Cambio hecho antes de generar o medir ningún clon.
- Recuperación tras 3 ventanas limpias seguidas, que no se aprenden; tope de 96
  actualizaciones por día una vez confiable; historia de 120 ventanas.

