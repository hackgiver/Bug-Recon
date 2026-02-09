# 🔍 Bug Bounty Recon Automation Script

## Description (English)

Automated reconnaissance script for bug bounty hunters that streamlines the entire discovery process. This tool orchestrates multiple industry-standard security tools in an optimized workflow to identify subdomains, verify live hosts, crawl websites, extract URLs, and detect potentially vulnerable parameters.

### Workflow:
1. **Subdomain Enumeration** → Discovers subdomains using Subfinder (passive/recursive) and Alterx (permutations)
2. **Live Host Verification** → Validates domains with dnsx (DNS resolution) and httpx (HTTP probing)
3. **Crawling & URL Extraction** → Collects URLs from multiple sources: GAU (historical), Waybackurls (archive), Katana (modern crawler), and Gospider (fast spider)
4. **URL Analysis** → Extracts additional URLs using Urlfinder from JavaScript and HTML files
5. **Vulnerability Pattern Detection** → Identifies potential attack vectors with GF patterns (XSS, SQLi, LFI, SSRF, RCE, Open Redirect, IDOR, Debug endpoints)

### Tools Used:
`subfinder` • `dnsx` • `httpx` • `gau` • `waybackurls` • `katana` • `gospider` • `urlfinder` • `alterx` • `gf`

---

## Descripción (Español)

Script automatizado de reconocimiento para bug bounty hunters que optimiza todo el proceso de descubrimiento. Esta herramienta orquesta múltiples herramientas de seguridad estándar de la industria en un flujo de trabajo optimizado para identificar subdominios, verificar hosts activos, rastrear sitios web, extraer URLs y detectar parámetros potencialmente vulnerables.

### Flujo de trabajo:
1. **Enumeración de Subdominios** → Descubre subdominios usando Subfinder (pasivo/recursivo) y Alterx (permutaciones)
2. **Verificación de Hosts Vivos** → Valida dominios con dnsx (resolución DNS) y httpx (sondeo HTTP)
3. **Crawling y Extracción de URLs** → Recopila URLs de múltiples fuentes: GAU (histórico), Waybackurls (archivo), Katana (crawler moderno) y Gospider (spider rápido)
4. **Análisis de URLs** → Extrae URLs adicionales usando Urlfinder desde archivos JavaScript y HTML
5. **Detección de Patrones de Vulnerabilidad** → Identifica vectores de ataque potenciales con patrones GF (XSS, SQLi, LFI, SSRF, RCE, Open Redirect, IDOR, endpoints de debug)

### Herramientas Utilizadas:
`subfinder` • `dnsx` • `httpx` • `gau` • `waybackurls` • `katana` • `gospider` • `urlfinder` • `alterx` • `gf`

---

## Quick Start

```bash
# Basic recon
./recon.sh example.com

# Full recon with crawling and vulnerability detection
./recon.sh example.com --all

# Deep recursive enumeration
./recon.sh example.com --deep

# Custom output directory
./recon.sh example.com -o /custom/path --all
