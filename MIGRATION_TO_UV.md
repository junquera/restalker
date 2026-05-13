# Migración a UV - Guía de Uso

## ¿Qué es UV?

**uv** es un gestor de paquetes Python ultrarrápido, escrito en Rust. Reemplaza a pip y poetry con una herramienta más eficiente y fácil de usar.

### Ventajas:
- ⚡ **100x más rápido** que pip
- 🔒 **Locks deterministas** (como poetry)
- 🎯 **Compatibilidad total** con pip y requirements.txt
- 📦 **Sin dependencias externas**
- 🐍 **Gestión automática de Python**

## Instalación

### Windows, macOS, Linux:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# O si tienes Homebrew:
brew install uv
```

Verifica la instalación:
```bash
uv --version
```

## Uso Básico

### 1. Instalar dependencias (CPU por defecto)
```bash
# Opción A: Desde pyproject.toml
uv sync

# Opción B: Desde requirements.txt
uv pip install -r requirements.txt

# Opción C: Instalar paquete individual
uv pip install nombre-paquete
```

### 2. Instalar con GPU (NVIDIA CUDA 12.1)
```bash
uv pip install -r requirements-gpu-cuda.txt
```

### 3. Instalar con GPU (AMD ROCm 6.0+)
```bash
uv pip install -r requirements-gpu-rocm.txt
```

### 4. Instalar dependencias de desarrollo
```bash
# Desde pyproject.toml
uv sync --extra dev

# O directamente
uv pip install pytest pytest-cov ruff
```

## Estructura del Proyecto

### `pyproject.toml` (NUEVO)
- Define metadatos del proyecto (nombre, versión, autor)
- Dependencias principales en `[project] dependencies`
- Dependencias opcionales en `[project.optional-dependencies]`
- Configuración de uv en `[tool.uv]`

### `requirements.txt` (actualizado)
- CPU-only (PyTorch sin CUDA)
- Compatible con `uv pip install -r requirements.txt`

### `requirements-gpu-cuda.txt` (actualizado)
- PyTorch con CUDA 12.1 (NVIDIA)
- Compatible con `uv pip install -r requirements-gpu-cuda.txt`

### `requirements-gpu-rocm.txt` (actualizado)
- PyTorch con ROCm 6.0 (AMD - Linux solo)
- Compatible con `uv pip install -r requirements-gpu-rocm.txt`

### `uv.lock` (auto-generado)
- Lock file determinista creado por uv
- **NO editar manualmente**
- Reemplaza a `poetry.lock`
- Hacer commit en git

### `poetry.lock` (ELIMINADO)
- Ya no se usa

## Comandos Comunes

```bash
# Sincronizar dependencias
uv sync

# Instalar desde requirements.txt
uv pip install -r requirements.txt

# Instalar dependencias opcionales
uv pip install -e ".[gpu]"

# Actualizar a versiones más nuevas
uv pip install --upgrade -r requirements.txt

# Ver qué está instalado
uv pip list

# Desinstalar paquete
uv pip uninstall nombre-paquete

# Ver dependencias (árbol)
uv pip tree

# Crear entorno virtual
uv venv .venv

# Activar entorno virtual
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Ejecutar código Python
uv run python script.py

# Ejecutar tests
uv run pytest

# Linting/formatting
uv run ruff check .
uv run ruff format .
```

## Transición desde Poetry

### Lo que cambió:
| Poetry | UV |
|--------|-----|
| `poetry install` | `uv sync` |
| `poetry add pkg` | `uv pip install pkg` |
| `poetry install --extras gpu` | `uv sync --extra gpu` |
| `poetry.lock` | `uv.lock` |
| `pyproject.toml` (Poetry) | `pyproject.toml` (Estándar) |

### Lo que PERMANECE igual:
- `requirements*.txt` (ahora con uv)
- `pyproject.toml` (estructura más estándar pero compatible)
- Estructura del proyecto
- Tests, linting, formatos

## Configuración Avanzada

### Usar índices alternativos (ej: PyPI privado)
En `pyproject.toml`:
```toml
[tool.uv]
index-url = "https://pypi.example.com/simple"
```

O con línea de comandos:
```bash
uv pip install --index-url https://pypi.example.com/simple -r requirements.txt
```

### Usar versiones específicas de Python
```bash
uv venv --python 3.11 .venv
```

### Ejecutar con entorno específico
```bash
uv run --python 3.11 script.py
```

## Troubleshooting

### Error: `torch` not found
- Asegúrate de haber usado el archivo `requirements.txt` correcto
- Verifica: `uv pip list | grep torch`

### GPU no detectada
```bash
python -c "import torch; print(torch.cuda.is_available())"
```

### Limpiar caché
```bash
uv cache clean
```

### Reinstalar todo
```bash
uv cache clean
rm uv.lock
uv sync
```

## Más Información

- 📚 [Documentación oficial de UV](https://docs.astral.sh/uv/)
- 🔗 [Repositorio GitHub](https://github.com/astral-sh/uv)
- 💬 [Discord Community](https://discord.gg/astral)

## Resumen de la Migración

✅ Actualizado: `pyproject.toml` (formato estándar PEP 517)
✅ Actualizado: `requirements.txt` (con comandos uv)
✅ Actualizado: `requirements-gpu-cuda.txt` (con comandos uv)
✅ Actualizado: `requirements-gpu-rocm.txt` (con comandos uv)
✅ Creado: `.uvignore` (archivo de configuración)
✅ Eliminado: `poetry.lock` (será reemplazado por `uv.lock`)

🎉 **¡Proyecto migrado a UV!**
