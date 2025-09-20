# Actualización a spaCy

Esta rama del proyecto ha sido actualizada para utilizar [spaCy](https://spacy.io/) en lugar de NLTK para el procesamiento de lenguaje natural. Esta actualización proporciona varias ventajas:

## Beneficios de la migración a spaCy

1. **Rendimiento mejorado**: spaCy está optimizado para producción y ofrece mejor rendimiento.
2. **Pipeline integrado**: Pipeline completo de NLP en un solo objeto, en lugar de funciones aisladas.
3. **Reconocimiento de entidades mejorado**: Modelos NER (Named Entity Recognition) más precisos y modernos.
4. **Soporte multilingüe**: Modelos pre-entrenados disponibles en varios idiomas.
5. **Mantenimiento activo**: Actualizaciones frecuentes y amplio soporte de la comunidad.

## Configuración para usar spaCy

### 1. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 2. Configurar modelos de spaCy

Ejecuta el script de configuración para instalar automáticamente los modelos necesarios:

```bash
python setup_spacy.py
```

Alternativamente, puedes instalar los modelos manualmente:

```bash
# Para español (recomendado)
python -m spacy download es_core_news_md

# O para inglés
python -m spacy download en_core_web_md

# O la versión pequeña (más rápida pero menos precisa)
python -m spacy download en_core_web_sm
```

## Pruebas

Para probar la funcionalidad de extracción de entidades:

```bash
python test.py [ruta_archivo_texto]
```

Para probar específicamente la funcionalidad de análisis de texto:

```bash
python test_textan.py
```

## Cambios en el API

La API externa sigue siendo compatible con versiones anteriores. Las siguientes clases y métodos siguen funcionando de la misma manera:

- `reStalker` - La clase principal para extracción de entidades
- `TextAnalysis` - Análisis de texto para extracción de palabras clave y frases

## Nota para desarrolladores

Si estás desarrollando con esta biblioteca, ten en cuenta que internamente ahora utilizamos modelos de spaCy. El rendimiento y los resultados pueden variar ligeramente con respecto a la versión basada en NLTK.