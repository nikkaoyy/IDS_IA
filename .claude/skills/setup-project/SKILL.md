---
name: setup-project
description: >-
  Inicializa el andamiaje del proyecto: git init, pyproject.toml, estructura de directorios,
  configuración de ruff/pytest, y organización profesional del proyecto IDS.
when_to_use: >-
  Use when the user asks to set up the project, initialize git, add pyproject.toml,
  configure linting, or professionalize the project structure. Also for §5 Fase 0.
allowed-tools: Bash, Read, Write, Edit
---

# Setup del Proyecto IDS

## Pasos

### 1. Inicializar git

```bash
cd /home/nikka/Documentos/FRED/ids-proyecto/ids_project
git init
```

Crear `.gitignore`:
```
__pycache__/
*.pyc
*.pyo
.pytest_cache/
*.egg-info/
dist/
build/
.venv/
venv/
data/
models/*.joblib
notebooks/.ipynb_checkpoints/
.ruff_cache/
```

### 2. Crear pyproject.toml

```toml
[project]
name = "ids-ieee802-3"
version = "0.1.0"
description = "IDS basado en IA con huella digital IEEE 802.3"
requires-python = ">=3.10"
dependencies = [
    "numpy>=1.24",
    "pandas>=2.0",
    "scikit-learn>=1.3",
    "xgboost>=2.0",
    "scapy>=2.5",
    "joblib>=1.3",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "ruff>=0.1",
    "matplotlib>=3.7",
]

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "UP"]
ignore = ["E501"]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "-v --tb=short"
```

### 3. Crear estructura de directorios faltantes

```bash
mkdir -p tests scripts docs
touch tests/__init__.py
```

### 4. Primer commit

```bash
git add -A
git commit -m "feat: andamiaje inicial del proyecto IDS IEEE 802.3

- Estructura modular src/ con pipeline, modelos, extractor, simulador
- pyproject.toml con dependencias y configuración de ruff/pytest
- .gitignore para datos y modelos no versionados
- README.md y CONTEXT_UPGRADE.md con auditoría del estado actual"
```

### 5. Validación

```bash
git log --oneline  # Debe mostrar el commit
pip install -e ".[dev]"  # Instala en modo editable
ruff check src/  # Debe correr sin errores graves
```
