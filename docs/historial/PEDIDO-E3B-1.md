# PEDIDO-E3B-1 — la pila completa, la víctima apagada y el benigno que se comporta como la vida real

Repo: `/home/nikka/Documentos/FRED/IDS`, rama `main`, base `01d5710` (E3A cerrado).
Guardar en la raíz del repo como `PEDIDO-E3B-1.md`.

## Por qué este pedido es el que decide si E3 sirve

E3A dejó dos resultados que se contradicen en apariencia y hay que resolver aquí:

- **Los dos primeros niveles de clon se detectan casi siempre:** ingenuo 0,975 [0,925–1,000] y ritmo/tamaños
  1,000 [1,000–1,000], con latencia de 4,2 s frente a 10,0 s. Era esperable: el detector mira la pila, y en esos dos
  niveles el clon tiene otra pila.
- **Pero las falsas alarmas son 16,2 [9,4–23,7] por dispositivo-día**, dieciséis veces el presupuesto de E2, y
  **42 de las 43 las dispara una sola señal: `ipid_salto_log2`**. En Linux el IP-ID avanza por flujo, no por equipo;
  la señal mide el salto entre tramas consecutivas del equipo y, cuando una ventana mezcla dos conexiones, ese salto
  es aleatorio. En IoT lo rompe el mDNS con IP-ID 0.

Y un tercer dato, del análisis exploratorio del propio informe: **sin las dos señales de IP-ID la detección no baja
(0,975 y 1,000) y las falsas alarmas son 0**. Ese 0 es demasiado bueno para ser cierto: en el generador, TTL,
ventana del SYN y opciones son **constantes por equipo**. Un equipo real cambia de TTL al actualizarse, entra por
VPN, tiene dos interfaces o corre contenedores. Un perfil que nunca vio variación legítima no está probado.

Por eso la parte B tiene tres frentes y en este orden.

## Estado verificado (2026-11-14, sobre `01d5710`)

- `src/identidad.py`, `src/ventanas.py` con las señales nuevas en `Trama`, `scripts/lab/generar_clones.py`,
  `scripts/evaluar_identidad.py`, `configs/identidad.json`; pruebas de E3A: **31 passed, 1 xfailed** (corridas aquí).
- `MIN_VENTANAS_PERFIL = 12`; sin aprendizaje durante alerta; tope diario de actualizaciones.
- Dataset de ataques intacto: sha256 `7f06d099…a945`. **El holdout 20–29 sigue gastado y no se abre.**
- Sesiones de identidad: 20 propias de 15 min (semillas 77000–77019), 12 equipos por sesión, 4 episodios por sesión.
- `.venv/bin/python`; suite completa ~4 min.

## Bloque 1 — Arreglar la señal de IP-ID (declarado antes de medirlo)

1. El IP-ID se juzga **por flujo**, no por equipo: misma 5-tupla (o misma sesión TCP) para seguir su avance. Si un
   equipo tiene varias conexiones abiertas, cada una lleva su contador —que es lo que hacen Linux, Windows y macOS—.
2. `ipid_continuidad` y `ipid_salto_log2` se recalculan así. La señal por equipo no se borra en silencio: queda
   declarada como **descartada** en el informe, con la razón y la cifra de falsas alarmas que producía.
3. Se remide: **la detección no puede bajar** de 0,975 / 1,000 en los dos primeros niveles, y las falsas alarmas
   tienen que quedar dentro del presupuesto de E2 (≤1 por dispositivo-día). Si no baja la detección pero tampoco
   bajan las alarmas, la causa no era el IP-ID y se reporta.

Criterio: `reports/identidad_e3b.json` con el bloque `ipid` que compare antes (16,2) y después, y
`tests/test_identidad.py` con el caso de dos flujos simultáneos del mismo equipo que **no** dispara.

## Bloque 2 — Benigno con variación real (el bloque que puede hundir el resultado)

Sin esto, cualquier cifra de E3 es optimista y hay que decirlo. En `scripts/lab/generar_clones.py` (o un
`generar_variacion.py` nuevo, mismo estilo: semillas fijas, congelado):

1. **Actualización de sistema**: un equipo cambia TTL y ventana TCP a mitad de la sesión, una sola vez, y sigue con
   el valor nuevo (transición, no ruido).
2. **VPN**: un equipo pasa a tunelizar; su TTL baja en 1 y su ventana cambia mientras dura.
3. **Dos interfaces o contenedores**: el mismo equipo emitiendo con dos pilas distintas (dos TTL, dos ventanas).
4. **mDNS y descubrimiento** con IP-ID 0 intercalado en el tráfico normal.
5. **Deriva lenta**: un parámetro se mueve un poco cada 10 ventanas a lo largo de una sesión.

Con eso se mide, y esto es lo que decide: **tasa de falsas alarmas sobre equipos legítimos con variación** y
**proporción que cae en `no_confiable`**. Un detector que se calla a base de marcar todo como no confiable es un
detector apagado con otro nombre: el informe debe dar las dos cifras juntas, nunca una sin la otra.

Criterio: el generador de variación tiene su prueba (misma semilla, mismo pcap byte a byte) y la tabla
`con_variacion` en `reports/identidad_e3b.json`.

## Bloque 3 — Tercer nivel: clon de pila completa, y la víctima apagada

1. **Clon de pila completa**: MAC, TTL, ventana, opciones, IP-ID y ritmo iguales a la víctima. Es el nivel que
   debería romper el sistema; si no lo rompe, hay que explicar por qué con la cifra (¿lo delata el conflicto de
   sesión? ¿el SEQ? ¿el solapamiento de dos emisores con la misma MAC?).
2. **Víctima apagada**: la IP de la víctima reaparece con otra MAC sin que ella emita. Se mide detección y latencia.
3. **Conflicto de sesión**: misma IP con dos MAC a la vez, como señal propia (si no existe, se añade con su
   justificación: dos emisores con la misma IP es imposible en una red sana).

Criterio: tabla por nivel con detección, latencia y falsas alarmas, y la frase del artículo: **qué nivel de clon
rompe el sistema, con su cifra**. Si el clon de pila completa pasa desapercibido, se escribe así y se declara como
límite no resuelto.

## Bloque 4 — Contaminación y envenenamiento del perfil

1. **5 % y 20 % de contaminación**: el clon está presente durante el aprendizaje, antes de la alarma. Tiene que
   demostrarse que el perfil **no** lo absorbe (la regla de no aprender durante la alerta y el tope diario son las que
   deberían salvarlo; si no lo salvan, es un hallazgo).
2. **Ataque presente en todo el aprendizaje** con el 20 %: se reporta el deterioro de la detección frente a la
   condición limpia.
3. Medir por separado cuánto aporta cada defensa (sin aprendizaje en alerta, tope diario, `no_confiable`), apagándolas
   una a una. Una defensa que no cambia la cifra no se queda por bonita.

Criterio: tabla de contaminación 0 / 5 % / 20 % y la ablación de las tres defensas, en `reports/identidad_e3b.json`.

## Criterio de aceptación (pega la salida real)

```bash
cd ~/Documentos/FRED/IDS
.venv/bin/python -m pytest -o addopts="" -q tests/test_identidad.py tests/test_evaluar_identidad.py tests/test_generar_clones.py
.venv/bin/python scripts/evaluar_identidad.py --config configs/identidad.json --partes b
.venv/bin/python -c "import json;d=json.load(open('reports/identidad_e3b.json'));print(d['resumen'])"
```

y `docs/INFORME_E3B.md` con: tabla por nivel de clon (incluido el de pila completa), falsas alarmas con y sin
variación benigna, contaminación 0/5/20 %, ablación de defensas, y la frase final con la cifra de qué nivel rompe
el sistema.

## Lo que NO se toca

- El contrato de 52 columnas, `VERSION_ESQUEMA` 3.0, `COLUMNAS_MODELO`, y el dataset de ataques (`7f06d099…a945`).
- `scripts/lab/generar_trafico.py` y `generar_dataset_lab.py` (generador de ataques congelado).
- `src/anomalias.py` y sus reportes: ya cerraron su pedido.
- El holdout 20–29 y `scripts/evaluar_holdout.py`.
- E4, E5, E6. `data/*.csv`, `data/*.pcap`: fuera de git. Sin `git push`.

## Cierre

Un commit por bloque, `git status` limpio, `docs/ESTADO.md` actualizado, y un reporte de cinco líneas: falsas
alarmas después del arreglo del IP-ID, falsas alarmas con variación real, detección del clon de pila completa, efecto
de la contaminación al 20 %, y qué queda para E4.
