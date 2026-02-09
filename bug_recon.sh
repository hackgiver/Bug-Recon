#!/bin/bash

# Bug Bounty Reconnaissance Script
# Flujo optimizado para enumeración y crawling de dominios

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║         Bug Bounty Recon Automation Script          ║"
echo "╔═══════════════════════════════════════════════════════╗"
echo -e "${NC}"

# Verificar argumentos
if [ $# -lt 1 ]; then
    echo -e "${RED}[!] Uso: $0 <dominio> [opciones]${NC}"
    echo -e "${YELLOW}Opciones:${NC}"
    echo "  -d, --deep          Enumeración profunda (subfinder recursivo)"
    echo "  -c, --crawl         Activar crawling completo"
    echo "  -a, --all           Ejecutar todo el flujo completo"
    echo "  -o, --output DIR    Directorio de salida (default: recon_DOMAIN)"
    exit 1
fi

DOMAIN=$1
DEEP_ENUM=false
CRAWL=false
FULL_FLOW=false
OUTPUT_DIR="recon_${DOMAIN}"

# Parsear argumentos
shift
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--deep) DEEP_ENUM=true; shift ;;
        -c|--crawl) CRAWL=true; shift ;;
        -a|--all) FULL_FLOW=true; DEEP_ENUM=true; CRAWL=true; shift ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo -e "${RED}[!] Opción desconocida: $1${NC}"; exit 1 ;;
    esac
done

# Crear estructura de directorios
mkdir -p "$OUTPUT_DIR"/{subdomains,alive,crawling,urls,vulnerable_params}
cd "$OUTPUT_DIR" || exit 1

echo -e "${GREEN}[+] Directorio de trabajo: $(pwd)${NC}\n"

# ============================================
# FASE 1: ENUMERACIÓN DE SUBDOMINIOS
# ============================================
echo -e "${YELLOW}[*] FASE 1: Enumeración de subdominios${NC}"

SUBDOMAINS_FILE="subdomains/all_subdomains.txt"
SUBDOMAINS_VFS="subdomains/subdomains_vfs.txt"

# Subfinder - Enumeración pasiva
echo -e "${BLUE}[>] Ejecutando Subfinder...${NC}"
if [ "$DEEP_ENUM" = true ]; then
    subfinder -d "$DOMAIN" -recursive -rl 10 -o "$SUBDOMAINS_VFS"
else
    subfinder -d "$DOMAIN" -o "$SUBDOMAINS_FILE"
fi

# ASNmap omitido por preferencia del usuario

# Amass - Enumeración adicional (comentado por ser lento, descomentar si es necesario)
# echo -e "${BLUE}[>] Ejecutando Amass...${NC}"
# amass enum -passive -d "$DOMAIN" -o "subdomains/amass.txt"
# cat "subdomains/amass.txt" >> "$SUBDOMAINS_FILE"

# Alterx - Generación de subdominios con permutaciones (opcional)
echo -e "${BLUE}[>] Generando permutaciones con Alterx...${NC}"
cat "$SUBDOMAINS_FILE" | alterx -silent >> "subdomains/alterx.txt" 2>/dev/null
cat "subdomains/alterx.txt" >> "$SUBDOMAINS_FILE"

# Eliminar duplicados
sort -u "$SUBDOMAINS_FILE" -o "$SUBDOMAINS_FILE"
TOTAL_SUBS=$(wc -l < "$SUBDOMAINS_FILE")
echo -e "${GREEN}[✓] Total de subdominios encontrados: $TOTAL_SUBS${NC}\n"

# ============================================
# FASE 2: VERIFICACIÓN DE HOSTS VIVOS
# ============================================
echo -e "${YELLOW}[*] FASE 2: Verificación de hosts vivos${NC}"

ALIVE_FILE="alive/subdomains_vivos.txt"

# dnsx - Resolución DNS
echo -e "${BLUE}[>] Resolviendo con dnsx...${NC}"
cat "$SUBDOMAINS_FILE" | dnsx -silent -a -resp -o "alive/dnsx_resolved.txt"

# httpx - Verificación HTTP/HTTPS
echo -e "${BLUE}[>] Verificando servicios web con httpx...${NC}"
cat "$SUBDOMAINS_FILE" | httpx -silent -td -location -title -sc -mc 200,201,301,302,401,403 -o "$ALIVE_FILE"

ALIVE_COUNT=$(wc -l < "$ALIVE_FILE")
echo -e "${GREEN}[✓] Hosts vivos encontrados: $ALIVE_COUNT${NC}\n"

# ============================================
# FASE 3: CRAWLING Y EXTRACCIÓN DE URLs
# ============================================
if [ "$CRAWL" = true ]; then
    echo -e "${YELLOW}[*] FASE 3: Crawling y extracción de URLs${NC}"
    
    URLS_FILE="urls/all_urls.txt"
    
    # Extraer solo las URLs limpias de httpx
    grep -oP 'https?://[^\s]+' "$ALIVE_FILE" | cut -d' ' -f1 > "alive/clean_urls.txt"
    
    # GAU - Obtener URLs históricas
    echo -e "${BLUE}[>] Extrayendo URLs históricas con GAU...${NC}"
    cat "alive/clean_urls.txt" | gau --threads 5 >> "$URLS_FILE" 2>/dev/null
    
    # Waybackurls - URLs del Wayback Machine
    echo -e "${BLUE}[>] Extrayendo URLs de Wayback Machine...${NC}"
    cat "alive/clean_urls.txt" | waybackurls >> "$URLS_FILE" 2>/dev/null
    
    # Katana - Crawler moderno
    echo -e "${BLUE}[>] Crawling con Katana...${NC}"
    cat "alive/clean_urls.txt" | katana -silent -jc -kf all -d 3 >> "$URLS_FILE" 2>/dev/null
    
    # Gospider - Spider rápido para endpoints
    echo -e "${BLUE}[>] Crawling con Gospider...${NC}"
    gospider -S "alive/clean_urls.txt" -o "crawling/gospider" -c 10 -d 2 --quiet
    find crawling/gospider -type f -name "*.txt" -exec cat {} \; >> "$URLS_FILE" 2>/dev/null
    
    # Eliminar duplicados
    sort -u "$URLS_FILE" -o "$URLS_FILE"
    TOTAL_URLS=$(wc -l < "$URLS_FILE")
    echo -e "${GREEN}[✓] Total de URLs extraídas: $TOTAL_URLS${NC}\n"
    
    # ============================================
    # FASE 4: ANÁLISIS Y FILTRADO
    # ============================================
    echo -e "${YELLOW}[*] FASE 4: Análisis y filtrado de URLs${NC}"
    
    # Urlfinder - Extraer URLs de JavaScript y HTML
    echo -e "${BLUE}[>] Extrayendo URLs con Urlfinder...${NC}"
    cat "$URLS_FILE" | urlfinder -o "urls/urlfinder_output.txt" 2>/dev/null
    
    # Filtrar URLs interesantes (parámetros, archivos sensibles, etc.)
    echo -e "${BLUE}[>] Filtrando URLs interesantes...${NC}"
    grep -E '\?|=|\.js$|\.json$|\.xml$|\.txt$|\.log$|\.bak$|admin|login|api|v1|v2' "$URLS_FILE" > "urls/interesting_urls.txt"
    
    INTERESTING_COUNT=$(wc -l < "urls/interesting_urls.txt")
    echo -e "${GREEN}[✓] URLs interesantes: $INTERESTING_COUNT${NC}\n"
    
    # ============================================
    # FASE 5: ANÁLISIS DE PARÁMETROS VULNERABLES CON GF
    # ============================================
    echo -e "${YELLOW}[*] FASE 5: Análisis de parámetros vulnerables con GF${NC}"
    
    # GF - Grep Framework para identificar parámetros vulnerables
    echo -e "${BLUE}[>] Buscando patrones de vulnerabilidades...${NC}"
    
    # XSS
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para XSS...${NC}"
    cat "$URLS_FILE" | gf xss > "vulnerable_params/xss_params.txt" 2>/dev/null
    XSS_COUNT=$(wc -l < "vulnerable_params/xss_params.txt")
    echo -e "${GREEN}    [✓] Parámetros XSS: $XSS_COUNT${NC}"
    
    # SQLi
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para SQLi...${NC}"
    cat "$URLS_FILE" | gf sqli > "vulnerable_params/sqli_params.txt" 2>/dev/null
    SQLI_COUNT=$(wc -l < "vulnerable_params/sqli_params.txt")
    echo -e "${GREEN}    [✓] Parámetros SQLi: $SQLI_COUNT${NC}"
    
    # LFI (Local File Inclusion)
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para LFI...${NC}"
    cat "$URLS_FILE" | gf lfi > "vulnerable_params/lfi_params.txt" 2>/dev/null
    LFI_COUNT=$(wc -l < "vulnerable_params/lfi_params.txt")
    echo -e "${GREEN}    [✓] Parámetros LFI: $LFI_COUNT${NC}"
    
    # SSRF (Server-Side Request Forgery)
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para SSRF...${NC}"
    cat "$URLS_FILE" | gf ssrf > "vulnerable_params/ssrf_params.txt" 2>/dev/null
    SSRF_COUNT=$(wc -l < "vulnerable_params/ssrf_params.txt")
    echo -e "${GREEN}    [✓] Parámetros SSRF: $SSRF_COUNT${NC}"
    
    # RCE (Remote Code Execution)
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para RCE...${NC}"
    cat "$URLS_FILE" | gf rce > "vulnerable_params/rce_params.txt" 2>/dev/null
    RCE_COUNT=$(wc -l < "vulnerable_params/rce_params.txt")
    echo -e "${GREEN}    [✓] Parámetros RCE: $RCE_COUNT${NC}"
    
    # Open Redirect
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para Open Redirect...${NC}"
    cat "$URLS_FILE" | gf redirect > "vulnerable_params/redirect_params.txt" 2>/dev/null
    REDIRECT_COUNT=$(wc -l < "vulnerable_params/redirect_params.txt")
    echo -e "${GREEN}    [✓] Parámetros Redirect: $REDIRECT_COUNT${NC}"
    
    # IDOR (Insecure Direct Object Reference)
    echo -e "${BLUE}  [>] Buscando parámetros potenciales para IDOR...${NC}"
    cat "$URLS_FILE" | gf idor > "vulnerable_params/idor_params.txt" 2>/dev/null
    IDOR_COUNT=$(wc -l < "vulnerable_params/idor_params.txt")
    echo -e "${GREEN}    [✓] Parámetros IDOR: $IDOR_COUNT${NC}"
    
    # Endpoints de Debug/Debug Info
    echo -e "${BLUE}  [>] Buscando endpoints de debug...${NC}"
    cat "$URLS_FILE" | gf debug-pages > "vulnerable_params/debug_endpoints.txt" 2>/dev/null
    DEBUG_COUNT=$(wc -l < "vulnerable_params/debug_endpoints.txt")
    echo -e "${GREEN}    [✓] Endpoints Debug: $DEBUG_COUNT${NC}"
    
    # Parámetros interesantes generales
    echo -e "${BLUE}  [>] Buscando parámetros interesantes...${NC}"
    cat "$URLS_FILE" | gf interestingparams > "vulnerable_params/interesting_params.txt" 2>/dev/null
    PARAMS_COUNT=$(wc -l < "vulnerable_params/interesting_params.txt")
    echo -e "${GREEN}    [✓] Parámetros interesantes: $PARAMS_COUNT${NC}"
    
    # Consolidar todos los parámetros vulnerables
    cat vulnerable_params/*.txt 2>/dev/null | sort -u > "vulnerable_params/all_vulnerable_params.txt"
    TOTAL_VULNS=$(wc -l < "vulnerable_params/all_vulnerable_params.txt")
    echo -e "${GREEN}[✓] Total de parámetros potencialmente vulnerables: $TOTAL_VULNS${NC}\n"
fi

# ============================================
# RESUMEN FINAL
# ============================================
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                  RESUMEN DE RESULTADOS                ║"
echo "╠═══════════════════════════════════════════════════════╣"
echo "║ Dominio objetivo: $DOMAIN"
echo "║ Subdominios encontrados: $TOTAL_SUBS"
echo "║ Hosts vivos: $ALIVE_COUNT"
if [ "$CRAWL" = true ]; then
    echo "║ URLs totales: $TOTAL_URLS"
    echo "║ URLs interesantes: $INTERESTING_COUNT"
fi
echo "╠═══════════════════════════════════════════════════════╣"
echo "║ Resultados guardados en: $(pwd)"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Generar reporte HTML simple
echo -e "${BLUE}[>] Generando reporte HTML...${NC}"
cat > report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Bug Bounty Recon - $DOMAIN</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #fff; }
        h1 { color: #4CAF50; }
        .section { margin: 20px 0; padding: 15px; background: #2d2d2d; border-radius: 5px; }
        .stat { font-size: 24px; font-weight: bold; color: #4CAF50; }
    </style>
</head>
<body>
    <h1>Bug Bounty Reconnaissance Report</h1>
    <h2>Dominio: $DOMAIN</h2>
    <div class="section">
        <h3>Estadísticas</h3>
        <p>Subdominios encontrados: <span class="stat">$TOTAL_SUBS</span></p>
        <p>Hosts vivos: <span class="stat">$ALIVE_COUNT</span></p>
$(if [ "$CRAWL" = true ]; then echo "        <p>URLs extraídas: <span class=\"stat\">$TOTAL_URLS</span></p>"; fi)
    </div>
    <div class="section">
        <h3>Archivos generados</h3>
        <ul>
            <li>Subdominios: subdomains/all_subdomains.txt</li>
            <li>Hosts vivos: alive/subdomains_vivos.txt</li>
$(if [ "$CRAWL" = true ]; then echo "            <li>URLs: urls/all_urls.txt</li>"; fi)
        </ul>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}[✓] Reporte HTML generado: report.html${NC}"
echo -e "${GREEN}[✓] Reconocimiento completado!${NC}"
