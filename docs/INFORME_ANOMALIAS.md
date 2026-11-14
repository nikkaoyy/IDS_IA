# Informe — detector de anomalías entrenado solo con benigno (PEDIDO-ANOMALIAS-1)

> Experimento de contraste sobre la base `72f5f8f` (extractor cerrado, esquema 3.0). Trabajo
> del 2026-11-14. Pedido: `PEDIDO-ANOMALIAS-1.md`; bitácora: `PROGRESO-ANOMALIAS.md`; cifras:
> `reports/anomalias.json` y `reports/anomalias.md`. El holdout 20–29 no se abrió. No se tocó
> el extractor, ni el contrato de 52 columnas, ni `configs/e2.json`, ni los informes
> anteriores. Sin `git push`.

## Respuesta

**¿Un detector sin ataques en el entrenamiento sirve para ataques desconocidos, a ≤ 1 falsa
alarma por dispositivo-día? No.**

- El mejor detector, IsolationForest sobre las 38 columnas sin capa 2, detecta **0,185
  [0,132, 0,244]** de los episodios, con 1,16 [0,21, 2,29] FA/dispositivo-día medidas.
- No supera al supervisado evaluado sobre tipos no vistos, LOAO de XGBoost: **0,228 [0,168,
  0,286]**. Los IC se solapan, así que tampoco es peor de forma demostrable.
- Queda muy por debajo del supervisado con el tipo en el entrenamiento: **0,894 [0,856,
  0,936]**.

Lo que detecta son los ataques que mueven el volumen: el 0,476 de los episodios de ráfaga y
el 0,559 de mac_flooding. Pierde casi todo lo sigiloso (el 0,052 de los episodios suaves) y,
paradójicamente, los ataques que el extractor mejor caracteriza: icmp_flood **0,000** y
arp_spoofing **0,024**. Sus contadores de violación valen 0 en el 100 % del benigno, y un
IsolationForest no puede partir por una columna constante (§4).

## 1. Resumen en tabla

5 folds por sesión × 5 semillas (42–46, las de E2). El umbral sale de los puntajes benignos
limpios fuera de fold de 3 folds internos, para ≤ 1 FA/dispositivo-día. IC 95 % por
bootstrap: de episodios para el recall, de sesiones para las razones. 188 episodios, 873
dispositivos, 6,71 dispositivo-días.

| Modelo / conjunto | Recall episodio | Recall atacante | FA/disp-día | T. mediana (s) | PR-AUC ventana | Folds con FA de test > 1 |
|---|---|---|---|---|---|---|
| **isolation_forest / sin_capa2** (principal) | **0,185 [0,132, 0,244]** | 0,309 [0,225, 0,398] | 1,16 [0,21, 2,29] | 5 [5, 10] | 0,304 [0,259, 0,350] | 10/25 |
| lof / sin_capa2 | 0,132 [0,087, 0,181] | 0,219 [0,138, 0,291] | 1,16 [0,00, 2,84] | 5 [5, 10] | 0,451 [0,396, 0,516] | 5/25 |
| isolation_forest_pca / sin_capa2 | 0,133 [0,093, 0,177] | 0,233 [0,165, 0,301] | 1,28 [0,18, 2,83] | 5 [5, 10] | 0,286 [0,252, 0,325] | 11/25 |
| isolation_forest / completo | 0,170 [0,119, 0,227] | 0,289 [0,206, 0,379] | 1,28 [0,47, 2,38] | 5 [5, 10] | 0,238 [0,202, 0,278] | 9/25 |
| lof / completo | 0,113 [0,070, 0,156] | 0,198 [0,126, 0,270] | 0,83 [0,00, 2,08] | 5 [5, 10] | 0,439 [0,387, 0,502] | 5/25 |
| isolation_forest_pca / completo | 0,168 [0,119, 0,220] | 0,297 [0,212, 0,377] | 0,51 [0,00, 1,26] | 5 [5, 10] | 0,247 [0,213, 0,285] | 5/25 |

**Gana IsolationForest sobre `sin_capa2`**, aunque los IC de las seis corridas se solapan
entre sí: ningún modelo es mejor que otro de forma demostrable. Añadir la capa 2 no ayuda: 0,170 frente a
0,185. Que el objetivo se supere en 10 de 25 folds se debe a la granularidad: un fold de
test tiene ≈ 1,4 dispositivo-días, así que una sola alarma ya son 0,73 FA/dispositivo-día y
dos superan el objetivo. La media medida (1,16) queda dentro del IC del objetivo. **El
objetivo no se relajó.**

## 2. La comparación que importa

Recall por episodio con el mismo presupuesto de ≤ 1 FA/dispositivo-día:

| Detector | ¿Vio el ataque? | Conjunto | Recall episodio | Fuente |
|---|---|---|---|---|
| Supervisado XGBoost, con el tipo en el entrenamiento | Sí | completo, 5 semillas | **0,894 [0,856, 0,936]** | `reports/evaluacion_e2.json` |
| Supervisado XGBoost, con el tipo en el entrenamiento | Sí | sin_capa2, semilla 42 | 0,829 [0,776, 0,878] | `reports/extractor/loao_it1_respuestas.json` |
| Supervisado XGBoost, LOAO (tipo excluido) | No ese tipo; sí los otros cinco | sin_capa2 | **0,228 [0,168, 0,286]** | ídem |
| Supervisado RF, LOAO | ídem | sin_capa2 | 0,068 [0,032, 0,105] | ídem |
| **Anomalías, IsolationForest** | **Ninguno** | sin_capa2, 5 semillas | **0,185 [0,132, 0,244]** | `reports/anomalias.json` |

Por tipo (todos los tipos son «no vistos» para el detector de anomalías):

| Tipo | Supervisado XGB con el tipo | Supervisado XGB LOAO | **IF sin_capa2** | LOF sin_capa2 | IF+PCA sin_capa2 |
|---|---|---|---|---|---|
| arp_spoofing | 0,912 | 0,294 | **0,024** [0,000, 0,071] | 0,218 | 0,118 |
| dns_spoofing | 0,867 | 0,100 | **0,073** [0,000, 0,180] | 0,067 | 0,127 |
| icmp_flood | 0,806 | 0,161 | **0,000** [0,000, 0,000] | 0,335 | 0,006 |
| mac_flooding | 1,000 | 0,265 | **0,559** [0,412, 0,707] | 0,029 | 0,188 |
| port_scan | 0,786 | 0,321 | **0,179** [0,036, 0,321] | 0,000 | 0,143 |
| syn_flood | 0,968 | 0,226 | **0,252** [0,123, 0,394] | 0,129 | 0,213 |

Por intensidad (IF, sin_capa2): ráfaga **0,476** [0,324, 0,647] (n = 34), media 0,223
[0,129, 0,326] (n = 62), suave **0,052** [0,011, 0,098] (n = 92). El pedido sospechaba que
fallarían icmp_flood y las ráfagas. Lo primero se cumple; lo segundo es al revés: las
ráfagas son lo único que el detector ve con cierta fiabilidad.

## 3. Sonda de deriva

Dispositivos legítimos con más falsas alarmas (media de las 5 semillas):

| Corrida | FA totales | MAC con alguna FA | Cuota de las 5 primeras | Peor dispositivo (FA en 15 min → FA/disp-día) |
|---|---|---|---|---|
| **IF / sin_capa2** | 7,8 | 11 de 854 | 69 % | `a4:83:e7:cf:70:df`: 1,4 → **135** (18 %) |
| LOF / sin_capa2 | 7,8 | **2 de 854** | **100 %** | `f4:8e:38:8a:25:c1`: 4,4 → **435** (56 %) |
| IF+PCA / sin_capa2 | 8,6 | 7 de 854 | 93 % | `3c:52:82:cb:0c:43`: 3,2 → 322 (37 %) |
| IF / completo | 8,6 | 10 de 854 | 84 % | `3c:52:82:c0:0b:8f`: 3,0 → 288 (35 %) |
| LOF / completo | 5,6 | 2 de 854 | 100 % | `3c:52:82:cb:0c:43`: 3,4 → 342 (61 %) |
| IF+PCA / completo | 3,4 | 3 de 854 | 100 % | `3c:52:82:cb:0c:43`: 2,0 → 201 (59 %) |

- **Las falsas alarmas no se reparten: se concentran en pocos equipos.** Con LOF, el 100 %
  cae en 2 de los 854 dispositivos. Un mismo equipo (`3c:52:82:cb:0c:43`, sesión única) es el
  más castigado en 4 de las 6 corridas. La media de ≈ 1 FA/dispositivo-día oculta que, para
  ese equipo, la tasa equivale a 200–435 FA/día.
- **Lo que no se puede medir:** ninguna MAC legítima aparece en más de una sesión, porque el
  generador crea los equipos por sesión (la única que se repite es la fila de efímeras). No
  hay forma de saber si el detector castigaría al mismo equipo día tras día. En producción,
  ese patrón haría que el detector se ignorase. Con este dataset solo se ve dentro de una
  sesión de 15 min.

## 4. Por qué falla donde falla (diagnóstico, medido después de las cifras)

- **IF es ciego a los contadores de violación.** 9 de las 38 columnas son constantes, o casi,
  en el benigno limpio. Cinco valen 0 en el 100 % de las 72 523 ventanas:
  `respuestas_no_solicitadas`, `tasa_respuestas_no_solicitadas`,
  `arp_replies_no_solicitadas`, `arp_ether_distinto_hwsrc` y `dns_respuestas_sin_consulta`.
  Cada árbol del IF se construye sobre 256 filas, y en esa submuestra esas columnas son
  constantes: no hay corte posible. Por eso icmp_flood (respuestas sin petición) y
  arp_spoofing (replies no solicitadas) se le pasan. En un detector que solo aprende el
  benigno, una regla «el contador debería valer 0» no se puede aprender.
- **LOF sí los ve, porque mide distancias.** Tras escalar, una columna constante conserva su
  valor en crudo, y un contador de 60 respuestas aleja la ventana de todo el benigno. Con
  eso detecta icmp_flood (0,335) y arp_spoofing (0,218). Pero pierde mac_flooding (0,029):
  sus MAC falsas emiten poco y quedan cerca del benigno de poco tráfico.
- **IF+PCA:** la limitación declarada antes de medir (satura fuera del rango del primer
  componente) se confirma en icmp_flood (0,006).
- IF y LOF se complementan por tipo. **No se combinaron**: hacerlo después de ver las cifras
  sería reajustar con el malicioso.

## 5. Lo que esto dice para el artículo

1. Un detector que no depende de haber visto el ataque es posible (0,185), pero, a un
   presupuesto de falsas alarmas operable, **no supera al supervisado LOAO** y está a 0,7 del
   supervisado con el ataque conocido. No es una vía para «ataques desconocidos» en este
   laboratorio.
2. Detecta volumen (ráfagas, mac_flooding), no violaciones de protocolo. Las violaciones son
   lo que mejor caracteriza el extractor, y son invisibles para el detector principal.
3. Sus falsas alarmas se concentran en uno o dos equipos por sesión. La cifra agregada
   oculta un patrón que en operación sería inaceptable.

## 6. Limitaciones

- Solo el dataset de desarrollo (20 sesiones). El holdout está gastado: no hay cifra limpia
  aparte.
- Hiperparámetros por defecto, fijados antes de medir. No se pueden elegir sin etiquetas sin
  hacer supervisado encubierto, así que otra configuración podría rendir distinto. No se
  exploró, a propósito.
- La deriva entre días no es medible con este generador (§3).
- El autoencoder quedó fuera: no hay framework de redes en el entorno.
- El objetivo de FA tiene granularidad gruesa por fold (≈ 0,73 FA/disp-día por alarma).

## 7. Criterio de aceptación — salida real

```
$ .venv/bin/python -m pytest -o addopts="" -q tests/test_anomalias.py
12 passed, 1 xfailed in 37.57s

$ .venv/bin/python scripts/evaluar_anomalias.py --config configs/anomalias.json
Escrito /home/nikka/Documentos/FRED/IDS/reports/anomalias.json y /home/nikka/Documentos/FRED/IDS/reports/anomalias.md
isolation_forest/sin_capa2: recall episodio 0.185 [0.132, 0.244] · FA/disp-día 1.16 [0.21, 2.29] · PR-AUC 0.304 [0.259, 0.350]
lof/sin_capa2: recall episodio 0.132 [0.087, 0.181] · FA/disp-día 1.16 [0.00, 2.84] · PR-AUC 0.451 [0.396, 0.516]
isolation_forest_pca/sin_capa2: recall episodio 0.133 [0.093, 0.177] · FA/disp-día 1.28 [0.18, 2.83] · PR-AUC 0.286 [0.252, 0.325]
isolation_forest/completo: recall episodio 0.170 [0.119, 0.227] · FA/disp-día 1.28 [0.47, 2.38] · PR-AUC 0.238 [0.202, 0.278]
lof/completo: recall episodio 0.113 [0.070, 0.156] · FA/disp-día 0.83 [0.00, 2.08] · PR-AUC 0.439 [0.387, 0.502]
isolation_forest_pca/completo: recall episodio 0.168 [0.119, 0.220] · FA/disp-día 0.51 [0.00, 1.26] · PR-AUC 0.247 [0.213, 0.285]

$ .venv/bin/python -c "import json;d=json.load(open('reports/anomalias.json'));print({k:v['resumen'] for k,v in d['resultados'].items()})"
{'isolation_forest/sin_capa2': {'recall_episodios': {'valor': 0.1851063829787234, 'ic95': [0.13191489361702127, 0.24361702127659574], 'n': 188}, 'recall_episodios_por_tipo': {'arp_spoofing': 0.024, 'dns_spoofing': 0.073, 'icmp_flood': 0.0, 'mac_flooding': 0.559, 'port_scan': 0.179, 'syn_flood': 0.252}, 'recall_atacantes': {'valor': 0.30927835051546393, 'ic95': [0.2246907216494846, 0.39798969072164947], 'n': 97}, 'falsas_alarmas_por_dispositivo_dia': {'valor': 1.162081303616847, 'ic95': [0.21095651713295646, 2.2850859418828313]}, 'pr_auc_ventana': {'valor': 0.30403584921524607, 'ic95': [0.25873523138418836, 0.3502027352119345]}, 'tiempo_deteccion_s_mediana': {'valor': 5.0, 'ic95': [5.0, 10.0], 'n': 37}}, 'lof/sin_capa2': {'recall_episodios': {'valor': 0.13191489361702127, 'ic95': [0.08720744680851066, 0.18085106382978725], 'n': 188}, 'recall_episodios_por_tipo': {'arp_spoofing': 0.218, 'dns_spoofing': 0.067, 'icmp_flood': 0.335, 'mac_flooding': 0.029, 'port_scan': 0.0, 'syn_flood': 0.129}, 'recall_atacantes': {'valor': 0.21855670103092784, 'ic95': [0.13814432989690723, 0.29072164948453605], 'n': 97}, 'falsas_alarmas_por_dispositivo_dia': {'valor': 1.162081303616847, 'ic95': [0.0, 2.8365372349401974]}, 'pr_auc_ventana': {'valor': 0.45090305018293986, 'ic95': [0.3959366322362616, 0.5162779148373431]}, 'tiempo_deteccion_s_mediana': {'valor': 5.0, 'ic95': [5.0, 10.0], 'n': 30}}, 'isolation_forest_pca/sin_capa2': {'recall_episodios': {'valor': 0.13297872340425532, 'ic95': [0.09255319148936171, 0.1766223404255319], 'n': 188}, 'recall_episodios_por_tipo': {'arp_spoofing': 0.118, 'dns_spoofing': 0.127, 'icmp_flood': 0.006, 'mac_flooding': 0.188, 'port_scan': 0.143, 'syn_flood': 0.213}, 'recall_atacantes': {'valor': 0.2329896907216495, 'ic95': [0.16494845360824742, 0.30103092783505153], 'n': 97}, 'falsas_alarmas_por_dispositivo_dia': {'valor': 1.2812691296288312, 'ic95': [0.1793745844918481, 2.8289026098042647]}, 'pr_auc_ventana': {'valor': 0.28559079108430707, 'ic95': [0.2515146276447753, 0.32478496109144983]}, 'tiempo_deteccion_s_mediana': {'valor': 5.0, 'ic95': [5.0, 10.0], 'n': 36}}, 'isolation_forest/completo': {'recall_episodios': {'valor': 0.1702127659574468, 'ic95': [0.11914893617021276, 0.22659574468085106], 'n': 188}, 'recall_episodios_por_tipo': {'arp_spoofing': 0.012, 'dns_spoofing': 0.073, 'icmp_flood': 0.0, 'mac_flooding': 0.559, 'port_scan': 0.164, 'syn_flood': 0.187}, 'recall_atacantes': {'valor': 0.28865979381443296, 'ic95': [0.20613402061855673, 0.37938144329896906], 'n': 97}, 'falsas_alarmas_por_dispositivo_dia': {'valor': 1.2812691296288312, 'ic95': [0.4653241059531761, 2.378771686650247]}, 'pr_auc_ventana': {'valor': 0.2380213757857288, 'ic95': [0.20204886568570185, 0.2777037188777172]}, 'tiempo_deteccion_s_mediana': {'valor': 5.0, 'ic95': [5.0, 10.0], 'n': 34}}, 'lof/completo': {'recall_episodios': {'valor': 0.11276595744680852, 'ic95': [0.07021276595744681, 0.1564095744680851], 'n': 188}, 'recall_episodios_por_tipo': {'arp_spoofing': 0.176, 'dns_spoofing': 0.067, 'icmp_flood': 0.232, 'mac_flooding': 0.059, 'port_scan': 0.0, 'syn_flood': 0.129}, 'recall_atacantes': {'valor': 0.1979381443298969, 'ic95': [0.12577319587628866, 0.27020618556701026], 'n': 97}, 'falsas_alarmas_por_dispositivo_dia': {'valor': 0.8343147820838901, 'ic95': [0.0, 2.0801773841584965]}, 'pr_auc_ventana': {'valor': 0.4390122146458483, 'ic95': [0.3870788975461398, 0.5022206148547493]}, 'tiempo_deteccion_s_mediana': {'valor': 5.0, 'ic95': [5.0, 10.0], 'n': 26}}, 'isolation_forest_pca/completo': {'recall_episodios': {'valor': 0.16808510638297874, 'ic95': [0.11914893617021276, 0.22023936170212768], 'n': 188}, 'recall_episodios_por_tipo': {'arp_spoofing': 0.194, 'dns_spoofing': 0.127, 'icmp_flood': 0.058, 'mac_flooding': 0.224, 'port_scan': 0.171, 'syn_flood': 0.226}, 'recall_atacantes': {'valor': 0.29690721649484536, 'ic95': [0.21237113402061858, 0.37731958762886597], 'n': 97}, 'falsas_alarmas_por_dispositivo_dia': {'valor': 0.5065482605509333, 'ic95': [0.0, 1.2613682317984267]}, 'pr_auc_ventana': {'valor': 0.2466203343541335, 'ic95': [0.21333623456120834, 0.28474487713645474]}, 'tiempo_deteccion_s_mediana': {'valor': 5.0, 'ic95': [5.0, 10.0], 'n': 38}}}
```

## 8. Commits

| Commit | Qué |
|---|---|
| `5962096` | Bloque 1: detector, CLI, configuración y pruebas |
| `7cfb9f4` | Bloque 2: evaluación completa |
| (este) | Bloque 3: este informe |

## 9. Lo que queda para Nico

1. Decidir si el artículo menciona el contraste. Propongo que sí, como resultado negativo: sin ver el ataque, 0,185 frente a 0,228 del LOAO y 0,894 con el ataque.
2. Si se quiere probar la combinación IF + LOF, o una regla de «contador ≠ 0» junto al detector de anomalías, hay que registrarla antes y medirla en sesiones nuevas (≥ 30), porque el holdout está gastado.
3. Para medir la deriva por equipo entre días hace falta un generador con equipos persistentes entre sesiones. El generador actual está congelado; sería otra etapa.
