# E3A — perfil de pila frente a clones de MAC: cifras

Generado por `scripts/evaluar_identidad.py` el 2026-11-14T01:10:23 en el commit `a496f2e09212ed73a16cb1b61e3887a882bb28bd` (árbol con cambios). 20 sesiones de `generar_clones.py` (semilla base 77000). IC 95 % con 1000 réplicas.

| Nivel | Episodios | Detección | Detección (acusables) | No acusables | Latencia mediana (s) | Latencia p90 (s) |
|---|---|---|---|---|---|---|
| ingenuo | 40 | 0.975 [0.925, 1.000] | 1.000 [1.000, 1.000] | 1 | 4.2 [3.0, 5.1] | 6.7 [5.7, 21.8] |
| ritmo | 40 | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1 | 10.0 [6.6, 17.0] | 33.3 [22.2, 51.6] |

## Legítimos

- Falsas alarmas por dispositivo-día: 16.19 [9.41, 23.67] (43 en 2.66 dispositivo-días, 260 dispositivos).
- Dispositivos con alguna falsa alarma: 0.092 [0.062, 0.123].
- Dispositivos que nunca llegan a `confiable`: 0.004 [0.000, 0.012].
- Ventanas en `no_confiable`: 0.139 [0.135, 0.144].

## Detección por par de pilas (víctima → clon)

| Nivel | Par | Detectados / episodios |
|---|---|---|
| ingenuo | android→iot | 1/1 |
| ingenuo | android→macos | 3/3 |
| ingenuo | android→windows | 1/1 |
| ingenuo | iot→android | 1/1 |
| ingenuo | iot→linux | 3/3 |
| ingenuo | iot→macos | 2/2 |
| ingenuo | iot→windows | 1/1 |
| ingenuo | linux→android | 2/2 |
| ingenuo | linux→iot | 4/4 |
| ingenuo | linux→macos | 1/1 |
| ingenuo | linux→windows | 3/3 |
| ingenuo | macos→android | 1/1 |
| ingenuo | macos→iot | 4/4 |
| ingenuo | macos→linux | 2/2 |
| ingenuo | macos→windows | 4/4 |
| ingenuo | windows→android | 2/2 |
| ingenuo | windows→iot | 2/3 |
| ingenuo | windows→linux | 1/1 |
| ingenuo | windows→macos | 1/1 |
| ritmo | android→iot | 5/5 |
| ritmo | android→macos | 3/3 |
| ritmo | android→windows | 1/1 |
| ritmo | iot→android | 3/3 |
| ritmo | iot→linux | 1/1 |
| ritmo | iot→macos | 4/4 |
| ritmo | iot→windows | 4/4 |
| ritmo | linux→iot | 2/2 |
| ritmo | linux→macos | 1/1 |
| ritmo | linux→windows | 2/2 |
| ritmo | macos→android | 1/1 |
| ritmo | macos→windows | 4/4 |
| ritmo | windows→android | 4/4 |
| ritmo | windows→iot | 2/2 |
| ritmo | windows→linux | 1/1 |
| ritmo | windows→macos | 2/2 |

## Dispositivos legítimos con más falsas alarmas

| Sesión | MAC | FA | Segundos | ¿Víctima en otro momento? |
|---|---|---|---|---|
| clones_006 | `02:05:04:0d:12:dc` | 5 | 895 | no |
| clones_000 | `02:ac:2b:f1:d5:27` | 4 | 900 | no |
| clones_012 | `02:32:32:cf:af:5e` | 3 | 905 | no |
| clones_012 | `02:7b:99:b7:23:d1` | 3 | 905 | no |
| clones_016 | `02:8e:e1:1c:e5:2c` | 3 | 895 | sí |
