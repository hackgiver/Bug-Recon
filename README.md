# Recon + JS Discovery + Nuclei (Audit / Bug Bounty)

------------------------------------------------------------------------

## Overview

This script automates a web security reconnaissance workflow for a
target domain. It combines subdomain enumeration, DNS resolution, HTTP
probing, endpoint discovery (historical and crawler-based), JavaScript
discovery and analysis, endpoint extraction from JavaScript, and Nuclei
scanning.

The objective is to generate a structured dataset of assets and
prioritized endpoints for manual security testing or controlled
automated analysis.

Designed for:

-   Security audits (maximum coverage)
-   Bug bounty engagements (low noise / high signal)

------------------------------------------------------------------------

## Execution Modes

At startup, the script prompts for an execution mode.

### Audit Mode (Maximum Coverage)

-   Broad reconnaissance scope
-   Extended Nuclei template coverage
-   Optional passive or aggressive scanning profile
-   Includes scanning across all validated endpoints

### Bug Bounty Mode (Low Noise)

-   Reduced scanning surface
-   Focus on high-value targets
-   Minimizes unnecessary traffic
-   Skips full endpoint-wide Nuclei scans by design

------------------------------------------------------------------------

## Requirements / Dependencies

The following tools must be installed and accessible in PATH:

-   subfinder --- Subdomain enumeration (ProjectDiscovery)
-   dnsx --- DNS resolution (ProjectDiscovery)
-   httpx --- HTTP probing and metadata extraction (ProjectDiscovery)
-   gau --- Historical URL collection
-   katana --- Web crawler (ProjectDiscovery)
-   uro --- URL normalization and cleanup
-   anew --- Incremental deduplication
-   gf --- Pattern-based filtering (XSS, SQLi, SSRF, etc.)
-   jq --- JSON processor
-   nuclei --- Template-based vulnerability scanner
-   pipx --- Executes LinkFinder directly from Git
-   timeout --- Execution timeout control (GNU coreutils)

LinkFinder is executed dynamically via:

git+https://github.com/GerbenJavado/LinkFinder.git

Nuclei templates must exist in:

\$HOME/nuclei-templates\
or\
/usr/share/nuclei-templates

If templates are missing:

nuclei -update-templates

------------------------------------------------------------------------

## Output Structure

The script creates a timestamped directory:

recon\_`<domain>`{=html}\_YYYYMMDD_HHMMSS/

Directory layout:

subdomains/ → subdomain discovery and HTTP classification\
endpoints/ → discovered endpoints (crawler + historical + JS)\
js-files/ → JavaScript discovery and validation\
gf-output/ → endpoints filtered by vulnerability pattern\
live-params/ → validated parameterized URLs\
nuclei-output/ → Nuclei scan results\
meta/ → metadata and JSON outputs\
REPORT.txt → final summary report

------------------------------------------------------------------------

## Workflow

### 1. Subdomain Enumeration

Uses subfinder to enumerate subdomains.

### 2. DNS Resolution

Resolves domains using dnsx.

### 3. HTTP Probing

httpx identifies active HTTP services and collects metadata.

Tracked status codes: 200, 201, 301, 302, 401, 403, 405, 500

### 3.1 Status Classification

Hosts are grouped by HTTP response code: - Normal hosts (2xx / 3xx) -
Access‑restricted hosts (401 / 403 / 405)

### 4. Endpoint Discovery

GAU collects historical URLs.\
Katana performs active crawling with JavaScript parsing enabled.\
Both datasets are merged into a unified endpoint list.

### 5. JavaScript Discovery

JavaScript files are extracted from multiple sources and validated using
httpx.

### 5.6 JavaScript Analysis (LinkFinder)

Each JavaScript file is analyzed using LinkFinder to extract hidden
endpoints. Results are normalized, validated, and merged into the global
endpoint dataset.

### 6. Pattern Filtering (GF)

Endpoints are filtered using patterns such as: xss, sqli, ssti, ssrf,
lfi, rce, idor, redirect, debug, interestingparams, upload-fields, json,
api, cors.

### 7. Parameter Validation

Candidate URLs are validated using httpx.

### 8. Nuclei Scanning

Runs Nuclei against: - Live JavaScript files - Validated parameter
endpoints

Severity levels: low, medium, high, critical

### 9. Audit Mode Only

In audit mode, all validated endpoints are scanned with Nuclei. Bug
bounty mode intentionally skips this step.

### 10. Final Report

REPORT.txt includes:

-   Template inventory
-   Asset counts
-   Endpoint statistics
-   JavaScript analysis results
-   Parameter validation metrics
-   Nuclei output references

------------------------------------------------------------------------

## Operational Notes

-   The workflow operates without authentication by default.
-   Results depend on target behavior, rate limiting, and historical
    data availability.
-   Execution must remain within authorized scope.
-   Designed as a reconnaissance and prioritization pipeline.

------------------------------------------------------------------------

## 🇪🇸 Descripción General

Este script automatiza un flujo de reconocimiento de seguridad web para
un dominio objetivo. Combina enumeración de subdominios, resolución DNS,
análisis HTTP, descubrimiento de endpoints (históricos y mediante
crawling), descubrimiento y análisis de archivos JavaScript, extracción
de endpoints desde JavaScript y escaneo con Nuclei.

El objetivo es generar un conjunto estructurado de activos y endpoints
priorizados para pruebas manuales de seguridad o análisis automatizado
controlado.

Diseñado para:

-   Auditorías de seguridad (máxima cobertura)
-   Programas de bug bounty (mínimo ruido / alta señal)

------------------------------------------------------------------------

## Modos de Ejecución

Al iniciar, el script solicita el modo de ejecución.

### Modo Auditoría (Máxima Cobertura)

-   Reconocimiento más amplio
-   Mayor cobertura de templates de Nuclei
-   Perfil pasivo o agresivo configurable
-   Incluye escaneo sobre todos los endpoints validados

### Modo Bug Bounty (Bajo Ruido)

-   Superficie de escaneo reducida
-   Enfoque en objetivos de alto valor
-   Minimiza tráfico innecesario
-   Omite el escaneo completo de todos los endpoints por diseño

------------------------------------------------------------------------

## Requisitos / Dependencias

Las siguientes herramientas deben estar instaladas y disponibles en
PATH:

-   subfinder --- Enumeración de subdominios (ProjectDiscovery)
-   dnsx --- Resolución DNS (ProjectDiscovery)
-   httpx --- Verificación HTTP y extracción de metadatos
    (ProjectDiscovery)
-   gau --- Recolección histórica de URLs
-   katana --- Crawler web (ProjectDiscovery)
-   uro --- Normalización y limpieza de URLs
-   anew --- Deduplicación incremental
-   gf --- Filtrado por patrones (XSS, SQLi, SSRF, etc.)
-   jq --- Procesador JSON
-   nuclei --- Escáner basado en templates
-   pipx --- Ejecuta LinkFinder directamente desde Git
-   timeout --- Control de tiempo de ejecución

LinkFinder se ejecuta dinámicamente desde:

git+https://github.com/GerbenJavado/LinkFinder.git

Las plantillas de Nuclei deben existir en:

\$HOME/nuclei-templates\
o\
/usr/share/nuclei-templates

Si no existen:

nuclei -update-templates

------------------------------------------------------------------------

## Estructura de Salida

El script crea un directorio con timestamp:

recon\_`<dominio>`{=html}\_YYYYMMDD_HHMMSS/

Estructura:

subdomains/ → descubrimiento de subdominios y clasificación HTTP\
endpoints/ → endpoints descubiertos (crawler + histórico + JS)\
js-files/ → descubrimiento y validación de JavaScript\
gf-output/ → endpoints filtrados por patrón de vulnerabilidad\
live-params/ → URLs con parámetros validadas\
nuclei-output/ → resultados de Nuclei\
meta/ → metadatos y salidas JSON\
REPORT.txt → reporte resumen final

------------------------------------------------------------------------

## Flujo de Trabajo

### 1. Enumeración de Subdominios

Se utiliza subfinder para enumerar subdominios.

### 2. Resolución DNS

dnsx valida los dominios resolubles.

### 3. Verificación HTTP

httpx detecta servicios HTTP activos y recopila metadatos.

Códigos monitorizados: 200, 201, 301, 302, 401, 403, 405, 500

### 3.1 Clasificación por Estado

Los hosts se agrupan por código HTTP: - Hosts normales (2xx / 3xx) -
Hosts restringidos (401 / 403 / 405)

### 4. Descubrimiento de Endpoints

GAU recopila URLs históricas.\
Katana realiza crawling activo con análisis de JavaScript.\
Ambos resultados se fusionan en una lista unificada.

### 5. Descubrimiento de JavaScript

Los archivos JS se extraen desde múltiples fuentes y se validan con
httpx.

### 5.6 Análisis de JavaScript (LinkFinder)

Cada archivo JS se analiza con LinkFinder para descubrir endpoints
ocultos. Los resultados se normalizan, validan y se integran en el
dataset global.

### 6. Filtrado por Patrones (GF)

Los endpoints se filtran usando patrones como: xss, sqli, ssti, ssrf,
lfi, rce, idor, redirect, debug, interestingparams, upload-fields, json,
api, cors.

### 7. Validación de Parámetros

Las URLs candidatas se validan usando httpx.

### 8. Escaneo con Nuclei

Se ejecuta Nuclei sobre: - Archivos JavaScript vivos - Endpoints con
parámetros validados

Severidades: low, medium, high, critical

### 9. Solo Modo Auditoría

En modo auditoría se escanean todos los endpoints validados. El modo bug
bounty omite este paso intencionadamente.

### 10. Reporte Final

REPORT.txt incluye:

-   Inventario de templates
-   Conteo de activos
-   Estadísticas de endpoints
-   Resultados del análisis JS
-   Métricas de validación de parámetros
-   Referencias de resultados Nuclei

------------------------------------------------------------------------

## Notas Operativas

-   El flujo funciona sin autenticación por defecto.
-   Los resultados dependen del comportamiento del objetivo y
    limitaciones de red.
-   Debe ejecutarse únicamente dentro de un alcance autorizado.
-   Diseñado como pipeline de reconocimiento y priorización, no como
    auditor automático completo.
