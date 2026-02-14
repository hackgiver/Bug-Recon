#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# -----------------------------
# Colors
# -----------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# -----------------------------
# Helpers
# -----------------------------
die(){ echo -e "${RED}[!] $*${NC}" >&2; exit 1; }
info(){ echo -e "${BLUE}[*] $*${NC}"; }
ok(){ echo -e "${GREEN}[+] $*${NC}"; }
warn(){ echo -e "${YELLOW}[!] $*${NC}"; }

need(){ command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
have_flag(){ "$1" -h 2>&1 | grep -q -- "$2"; }

# Grep that must NOT kill the script when no matches are found.
# Usage: ... | grep_or_empty -E 'pattern' | ...
grep_or_empty() { grep "$@" || true; }

# -----------------------------
# Banner
# -----------------------------
echo -e "${BLUE}"
echo "================================================"
echo "   RECON + JS DISCOVERY + NUCLEI (AUDIT/BB)"
echo "================================================"
echo -e "${NC}"

# -----------------------------
# Args
# -----------------------------
if [[ -z "${1:-}" ]]; then
  echo -e "${RED}[!] Usage: $0 <domain>${NC}"
  echo -e "${YELLOW}[*] Example: $0 example.com${NC}"
  exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"

# -----------------------------
# Deps
# -----------------------------
for bin in subfinder dnsx httpx gau katana nuclei uro anew gf jq pipx timeout; do need "$bin"; done

# LinkFinder via pipx run
LF_REPO="git+https://github.com/GerbenJavado/LinkFinder.git"

# -----------------------------
# Mode selector
# -----------------------------
echo -e "${YELLOW}[?]${NC} ¿Modo de trabajo?"
echo "  1) Auditoría (máxima cobertura)"
echo "  2) Bug bounty (mínimo ruido / alta señal)"
read -rp "> " MODE_CHOICE

MODE="bb"
[[ "$MODE_CHOICE" == "1" ]] && MODE="audit"

NUCLEI_PROFILE="bb-default"
NUCLEI_RL=80
NUCLEI_C=15
NUCLEI_MAX_HOST_ERROR=30
NUCLEI_RETRIES=1
NUCLEI_TIMEOUT=10

if [[ "$MODE" == "audit" ]]; then
  echo -e "${YELLOW}[?]${NC} Auditoría: ¿Nuclei pasivo o agresivo?"
  echo "  1) Pasivo (menos rate-limit, más estable)"
  echo "  2) Agresivo (más rápido, más ruido/429)"
  read -rp "> " AGG
  if [[ "$AGG" == "2" ]]; then
    NUCLEI_PROFILE="audit-aggressive"
    NUCLEI_RL=200
    NUCLEI_C=40
    NUCLEI_MAX_HOST_ERROR=120
    NUCLEI_RETRIES=2
    NUCLEI_TIMEOUT=12
  else
    NUCLEI_PROFILE="audit-passive"
    NUCLEI_RL=80
    NUCLEI_C=15
    NUCLEI_MAX_HOST_ERROR=80
    NUCLEI_RETRIES=1
    NUCLEI_TIMEOUT=12
  fi
fi

ok "Mode: $MODE | Nuclei profile: $NUCLEI_PROFILE (rl=$NUCLEI_RL c=$NUCLEI_C max-host-error=$NUCLEI_MAX_HOST_ERROR retries=$NUCLEI_RETRIES timeout=$NUCLEI_TIMEOUT)"
echo

# -----------------------------
# Dirs
# -----------------------------
mkdir -p "$OUTPUT_DIR"/{subdomains,endpoints,js-files,gf-output,live-params,nuclei-output,meta}
mkdir -p "$OUTPUT_DIR"/subdomains/{by-status,normal,bypass}
cd "$OUTPUT_DIR"
ok "Output directory: $OUTPUT_DIR"
echo

# -----------------------------
# Nuclei templates root (modern layout)
# -----------------------------
if [[ -d "$HOME/nuclei-templates" ]]; then
  TROOT="$HOME/nuclei-templates"
elif [[ -d "/usr/share/nuclei-templates" ]]; then
  TROOT="/usr/share/nuclei-templates"
else
  die "No nuclei-templates dir found. Run: nuclei -update-templates"
fi

T_HTTP="$TROOT/http"
T_SSL="$TROOT/ssl"
T_DNS="$TROOT/dns"
T_NETWORK="$TROOT/network"
T_CLOUD="$TROOT/cloud"
T_FILE="$TROOT/file"
T_JAVASCRIPT="$TROOT/javascript"
T_WORKFLOWS="$TROOT/workflows"

count_tpls() {
  local d="$1"
  if [[ -d "$d" ]]; then
    find "$d" -type f -name '*.yaml' 2>/dev/null | wc -l
  else
    echo 0
  fi
}

info "Template inventory (yaml count) in: $TROOT"
echo "  http:       $(count_tpls "$T_HTTP")"
echo "  ssl:        $(count_tpls "$T_SSL")"
echo "  dns:        $(count_tpls "$T_DNS")"
echo "  network:    $(count_tpls "$T_NETWORK")"
echo "  cloud:      $(count_tpls "$T_CLOUD")"
echo "  file:       $(count_tpls "$T_FILE")"
echo "  javascript: $(count_tpls "$T_JAVASCRIPT")"
echo "  workflows:  $(count_tpls "$T_WORKFLOWS")"
echo

# -----------------------------
# Nuclei runners (modern template sets)
# -----------------------------
NUCLEI_SET_BB=( "$T_HTTP" "$T_JAVASCRIPT" "$T_FILE" )
NUCLEI_SET_AUDIT=( "$T_HTTP" "$T_SSL" "$T_DNS" "$T_NETWORK" "$T_CLOUD" "$T_FILE" "$T_JAVASCRIPT" )

run_nuclei() {
  local input="$1"
  local out="$2"
  shift 2
  local -a tdirs=( "$@" )

  [[ -s "$input" ]] || { warn "No targets for nuclei: $input"; return 0; }

  info "Nuclei scanning -> $out"
  # shellcheck disable=SC2046
  nuclei -l "$input" \
    $(for d in "${tdirs[@]}"; do echo -n "-t \"$d\" "; done) \
    -severity low,medium,high,critical \
    -exclude-severity info \
    -rl "$NUCLEI_RL" -c "$NUCLEI_C" \
    -max-host-error "$NUCLEI_MAX_HOST_ERROR" \
    -retries "$NUCLEI_RETRIES" -timeout "$NUCLEI_TIMEOUT" \
    -stats -silent \
    -o "$out" || true
}

# ============================================
# 1) SUBDOMAIN ENUMERATION
# ============================================
echo -e "${PURPLE}[TOOL: SUBFINDER]${NC}"
info "Running subfinder..."
subfinder -d "$DOMAIN" -all -silent -o subdomains/subfinder.txt
ok "Subfinder results: $(wc -l < subdomains/subfinder.txt 2>/dev/null || echo 0)"
echo

sort -u subdomains/subfinder.txt | anew subdomains/all-subs.txt >/dev/null
ok "Total unique subdomains: $(wc -l < subdomains/all-subs.txt 2>/dev/null || echo 0)"
echo

# ============================================
# 2) DNS RESOLUTION
# ============================================
echo -e "${PURPLE}[TOOL: DNSX]${NC}"
info "Resolving DNS..."
cat subdomains/all-subs.txt | dnsx -silent -a -resp -o subdomains/dns-alive.txt
ok "DNS resolved: $(wc -l < subdomains/dns-alive.txt 2>/dev/null || echo 0)"
echo

# ============================================
# 3) HTTP PROBE
# ============================================
echo -e "${PURPLE}[TOOL: HTTPX]${NC}"
info "Probing HTTP services..."

cat subdomains/dns-alive.txt | awk '{print $1}' | \
  httpx -silent -mc 200,201,301,302,401,403,405,500 \
    -title -tech-detect -status-code -follow-redirects \
    -o subdomains/live-hosts.txt

ok "Live hosts (decorated): $(wc -l < subdomains/live-hosts.txt 2>/dev/null || echo 0)"
echo

awk '{print $1}' subdomains/live-hosts.txt | sed 's#/\+$##' | sort -u > subdomains/live-hosts.urls.txt

cat subdomains/dns-alive.txt | awk '{print $1}' | \
  httpx -silent -follow-redirects -json -o meta/httpx-hosts.jsonl >/dev/null

# ============================================
# 3.1) SPLIT BY STATUS
# ============================================
echo -e "${BLUE}[*] Step 3.1: Splitting hosts by status...${NC}"

jq -r 'select(.url != null and .status_code != null) | "\(.status_code)\t\(.url)"' meta/httpx-hosts.jsonl \
| awk -F'\t' '
  {
    code=$1; url=$2;
    gsub(/\/+$/, "", url);
    print url >> ("subdomains/by-status/" code ".txt")
  }
'

: > subdomains/normal/normal.txt
find subdomains/by-status -maxdepth 1 -type f -name "*.txt" -print0 \
| while IFS= read -r -d '' f; do
    code="$(basename "$f" .txt)"
    if [[ "$code" =~ ^2[0-9][0-9]$ || "$code" =~ ^3[0-9][0-9]$ ]]; then
      cat "$f" >> subdomains/normal/normal.txt
    fi
  done
sort -u subdomains/normal/normal.txt > subdomains/normal/live-hosts.txt || true

: > subdomains/bypass/bypass.txt
for code in 401 403 405; do
  if [[ -f "subdomains/by-status/${code}.txt" ]]; then
    mkdir -p "subdomains/bypass/${code}"
    cp "subdomains/by-status/${code}.txt" "subdomains/bypass/${code}/hosts.txt"
    cat "subdomains/by-status/${code}.txt" >> subdomains/bypass/bypass.txt
  fi
done
sort -u subdomains/bypass/bypass.txt > subdomains/bypass/bypass-hosts.txt || true

ok "Normal (2xx/3xx): $(wc -l < subdomains/normal/live-hosts.txt 2>/dev/null || echo 0)"
ok "Bypass candidates (401/403/405): $(wc -l < subdomains/bypass/bypass-hosts.txt 2>/dev/null || echo 0)"
echo

# ============================================
# 4) ENDPOINT DISCOVERY (GAU + KATANA)
# ============================================
echo -e "${PURPLE}[TOOL: GAU]${NC}"
info "Fetching historical endpoints..."

GAU_OUT_FLAG="--o"
gau -h 2>&1 | grep -qE '(^|\s)-o(\s|,)' && GAU_OUT_FLAG="-o"

cat subdomains/live-hosts.urls.txt | \
  gau --threads 10 \
    --blacklist png,jpg,gif,jpeg,svg,css,woff,woff2,ttf,eot,ico,pdf,zip,mp4,webm \
    $GAU_OUT_FLAG endpoints/gau-raw.txt

cat endpoints/gau-raw.txt | uro | anew endpoints/gau.txt >/dev/null
ok "GAU endpoints (cleaned): $(wc -l < endpoints/gau.txt 2>/dev/null || echo 0)"
echo

echo -e "${PURPLE}[TOOL: KATANA]${NC}"
info "Active crawling with Katana..."
cat subdomains/live-hosts.urls.txt | \
  katana -d 3 -jc -kf all -fs rdn \
    -ef png,jpg,gif,jpeg,svg,css,woff,woff2,ttf,eot,ico,pdf,zip,mp4,webm \
    -silent -nc -o endpoints/katana.txt

ok "Katana endpoints: $(wc -l < endpoints/katana.txt 2>/dev/null || echo 0)"
echo

cat endpoints/gau.txt endpoints/katana.txt | sort -u | anew endpoints/all-endpoints.txt >/dev/null
ok "Total unique endpoints (pre-JS): $(wc -l < endpoints/all-endpoints.txt 2>/dev/null || echo 0)"
echo

# ============================================
# 5) EXTRACT JS FILES
# ============================================
echo -e "${BLUE}[*] Step 5: Extracting JavaScript files...${NC}"

echo -e "${YELLOW}[*] Extracting JS from endpoint lists...${NC}"
cat endpoints/all-endpoints.txt | grep_or_empty -iE "\.js(\?|$|#)" | anew js-files/from-endpoints.txt >/dev/null

echo -e "${PURPLE}[TOOL: HTTPX - JS Discovery]${NC}"
echo -e "${YELLOW}[*] Extracting JS from live hosts source code...${NC}"
cat subdomains/live-hosts.urls.txt | \
  httpx -silent -mc 200 \
    -er '(?i)(https?://[^"'\''>\s]+\.js(?:\?[^"'\''>\s]*)?)' 2>/dev/null \
  | grep_or_empty -oE 'https?://[^"'\''>\s]+\.js[^"'\''>\s]*' \
  | anew js-files/from-source.txt >/dev/null

echo -e "${YELLOW}[*] Looking for JS in GAU/Katana output...${NC}"
cat endpoints/gau.txt endpoints/katana.txt | grep_or_empty -iE "\.js(\?|$|#)" | anew js-files/from-crawlers.txt >/dev/null

echo -e "${PURPLE}[TOOL: KATANA - JS CRAWL]${NC}"
echo -e "${YELLOW}[*] Katana JS crawl discovery...${NC}"
: > js-files/katana-js.txt

if have_flag katana "-js-crawl"; then
  cat subdomains/live-hosts.urls.txt | \
    katana -silent -nc -d 3 -js-crawl \
    | grep_or_empty -iE '\.js(\?|$|#)' \
    | sed 's/#.*$//' | sort -u > js-files/katana-js.txt || true
else
  warn "Katana doesn't show -js-crawl. Using fallback (-jc + regex extract)."
  cat subdomains/live-hosts.urls.txt | \
    katana -silent -nc -d 3 -jc \
    | grep_or_empty -oEi 'https?://[^"'\'' >]+\.js([^"'\'' >#]*)?' \
    | sed 's/#.*$//' | sort -u > js-files/katana-js.txt || true
fi

cat js-files/from-*.txt js-files/katana-js.txt 2>/dev/null | sed 's/#.*$//' | sort -u | anew js-files/all-js.txt >/dev/null
ok "Total JS files found: $(wc -l < js-files/all-js.txt 2>/dev/null || echo 0)"
echo

echo -e "${PURPLE}[TOOL: HTTPX - JS Validation]${NC}"
echo -e "${YELLOW}[*] Validating JS files...${NC}"
cat js-files/all-js.txt | httpx -silent -mc 200,403 -content-type -follow-redirects -o js-files/live-js.txt
ok "Live JS files: $(wc -l < js-files/live-js.txt 2>/dev/null || echo 0)"
echo

# ============================================
# 5.6) LINKFINDER -> endpoints/params from JS
# ============================================
echo -e "${PURPLE}[TOOL: LINKFINDER]${NC}"
echo -e "${BLUE}[*] Extracting endpoints/params from JS via pipx run...${NC}"

JS_OUT_RAW="endpoints/from-js.linkfinder.raw.txt"
JS_OUT_NORM="endpoints/from-js.linkfinder.normalized.txt"
JS_OUT_VALID="endpoints/from-js.linkfinder.validated.txt"
: > "$JS_OUT_RAW"
: > "$JS_OUT_NORM"
: > "$JS_OUT_VALID"

if [[ -s js-files/live-js.txt ]]; then
  while IFS= read -r js; do
    [[ -z "$js" ]] && continue
    origin="$(echo "$js" | awk -F/ '{print $1"//"$3}')"

    found="$(
      timeout 25s pipx run "$LF_REPO" -i "$js" -o cli 2>/dev/null \
      | sed 's/\r$//' \
      | sed 's/[[:space:]]\+$//' \
      | sed 's/^"//;s/"$//' \
      | grep_or_empty -vE '^(#|$)' \
      | head -n 5000 || true
    )"

    [[ -z "$found" ]] && continue
    printf '%s\n' "$found" >> "$JS_OUT_RAW"

    printf '%s\n' "$found" | while IFS= read -r u; do
      u="$(echo "$u" | sed 's/[),;]\+$//')"

      if echo "$u" | grep -qiE '^(javascript:|data:|mailto:|tel:)'; then
        continue
      fi

      if echo "$u" | grep -qiE '^https?://'; then
        echo "$u"
      elif [[ "$u" == /* ]]; then
        echo "${origin}${u}"
      else
        continue
      fi
    done >> "$JS_OUT_NORM"
  done < js-files/live-js.txt

  sort -u "$JS_OUT_RAW"  -o "$JS_OUT_RAW"  || true
  sort -u "$JS_OUT_NORM" -o "$JS_OUT_NORM" || true

  ok "LinkFinder raw findings: $(wc -l < "$JS_OUT_RAW" 2>/dev/null || echo 0)"
  ok "LinkFinder normalized endpoints: $(wc -l < "$JS_OUT_NORM" 2>/dev/null || echo 0)"

  if [[ -s "$JS_OUT_NORM" ]]; then
    cat "$JS_OUT_NORM" | httpx -silent -mc 200,201,301,302,401,403,405,500 -follow-redirects -o "$JS_OUT_VALID" || true
    ok "Validated JS-derived endpoints: $(wc -l < "$JS_OUT_VALID" 2>/dev/null || echo 0)"

    cat endpoints/all-endpoints.txt "$JS_OUT_NORM" | sort -u | anew endpoints/all-endpoints.merged.txt >/dev/null
    mv endpoints/all-endpoints.merged.txt endpoints/all-endpoints.txt
    ok "Total unique endpoints (after JS merge): $(wc -l < endpoints/all-endpoints.txt 2>/dev/null || echo 0)"
  fi
else
  warn "No live JS files for LinkFinder parsing"
fi
echo

# ============================================
# 6) GF PATTERNS
# ============================================
echo -e "${PURPLE}[TOOL: GF]${NC}"
echo -e "${BLUE}[*] Running GF patterns...${NC}\n"

patterns=(
  "xss" "sqli" "ssti" "ssrf" "lfi" "rce" "idor"
  "redirect" "debug" "interestingparams" "upload-fields"
  "json" "api" "cors"
)

for pattern in "${patterns[@]}"; do
  if [[ -f "$HOME/.gf/$pattern.json" ]]; then
    echo -e "${YELLOW}  [*] Pattern: $pattern${NC}"
    gf "$pattern" endpoints/all-endpoints.txt 2>/dev/null | uro > "gf-output/$pattern.txt" || true
    c=$(wc -l < "gf-output/$pattern.txt" 2>/dev/null || echo 0)
    [[ "$c" -gt 0 ]] && echo -e "${GREEN}      ✓ Found $c URLs${NC}" || echo -e "${RED}      ✗ No matches${NC}"
  else
    echo -e "${RED}  [!] Pattern not found: $pattern (skipping)${NC}"
  fi
done
echo

# ============================================
# 7) VALIDATE "PARAM" URLS (from GF)
# ============================================
echo -e "${PURPLE}[TOOL: HTTPX - Parameter Validation]${NC}"
echo -e "${BLUE}[*] Validating GF-matched URLs (param candidates)...${NC}"

cat gf-output/*.txt 2>/dev/null | sort -u > live-params/all-params.txt || true
cat live-params/all-params.txt | httpx -silent -mc 200,201,301,302,401,403,405,500 -follow-redirects -o live-params/validated.txt || true
ok "Live params validated: $(wc -l < live-params/validated.txt 2>/dev/null || echo 0)"
echo

# ============================================
# 8) NUCLEI (BB: minimal / AUDIT: still useful on params)
# ============================================
if [[ "$MODE" == "audit" ]]; then
  run_nuclei "js-files/live-js.txt" "nuclei-output/nuclei_js_audit.txt" "${NUCLEI_SET_AUDIT[@]}"
  run_nuclei "live-params/validated.txt" "nuclei-output/nuclei_params_audit.txt" "${NUCLEI_SET_AUDIT[@]}"
else
  run_nuclei "js-files/live-js.txt" "nuclei-output/nuclei_js_bb.txt" "${NUCLEI_SET_BB[@]}"
  run_nuclei "live-params/validated.txt" "nuclei-output/nuclei_params_bb.txt" "${NUCLEI_SET_BB[@]}"
fi
echo

# ============================================
# 9) AUDIT MODE: NUCLEI ON ALL LIVE ENDPOINTS (END)
# ============================================
LIVE_ALL="live-params/validated_all_endpoints.txt"
: > "$LIVE_ALL"

info "Validating ALL endpoints (for audit-wide nuclei scan)..."
cat endpoints/all-endpoints.txt | httpx -silent -mc 200,201,301,302,401,403,405,500 -follow-redirects -o "$LIVE_ALL" || true
ok "All-live validated endpoints: $(wc -l < "$LIVE_ALL" 2>/dev/null || echo 0)"
echo

if [[ "$MODE" == "audit" ]]; then
  run_nuclei "$LIVE_ALL" "nuclei-output/nuclei_all_live_audit.txt" "${NUCLEI_SET_AUDIT[@]}"
else
  warn "Bug bounty mode: skipping ALL-live nuclei scan (by design)."
fi
echo

# ============================================
# 10) SUMMARY REPORT
# ============================================
echo -e "${BLUE}[*] Generating summary report...${NC}"

cat > REPORT.txt <<EOF
==============================================
RECON SUMMARY FOR: $DOMAIN
Date: $(date)
Mode: $MODE
Nuclei profile: $NUCLEI_PROFILE
Templates root: $TROOT
==============================================

[TEMPLATES]
http:       $(count_tpls "$T_HTTP")
ssl:        $(count_tpls "$T_SSL")
dns:        $(count_tpls "$T_DNS")
network:    $(count_tpls "$T_NETWORK")
cloud:      $(count_tpls "$T_CLOUD")
file:       $(count_tpls "$T_FILE")
javascript: $(count_tpls "$T_JAVASCRIPT")
workflows:  $(count_tpls "$T_WORKFLOWS")

[SUBDOMAINS]
Total found: $(wc -l < subdomains/all-subs.txt 2>/dev/null || echo 0)
DNS resolved: $(wc -l < subdomains/dns-alive.txt 2>/dev/null || echo 0)
Live hosts (decorated): $(wc -l < subdomains/live-hosts.txt 2>/dev/null || echo 0)
Live hosts (urls-only): $(wc -l < subdomains/live-hosts.urls.txt 2>/dev/null || echo 0)

[ENDPOINTS]
GAU endpoints: $(wc -l < endpoints/gau.txt 2>/dev/null || echo 0)
Katana endpoints: $(wc -l < endpoints/katana.txt 2>/dev/null || echo 0)
Total unique endpoints (after JS merge): $(wc -l < endpoints/all-endpoints.txt 2>/dev/null || echo 0)

[JAVASCRIPT FILES]
Total unique JS: $(wc -l < js-files/all-js.txt 2>/dev/null || echo 0)
Live JS (200/403): $(wc -l < js-files/live-js.txt 2>/dev/null || echo 0)

[JS -> ENDPOINTS (LINKFINDER)]
Raw findings: $(wc -l < endpoints/from-js.linkfinder.raw.txt 2>/dev/null || echo 0)
Normalized endpoints: $(wc -l < endpoints/from-js.linkfinder.normalized.txt 2>/dev/null || echo 0)
Validated endpoints: $(wc -l < endpoints/from-js.linkfinder.validated.txt 2>/dev/null || echo 0)

[PARAMS (GF)]
Total candidates: $(wc -l < live-params/all-params.txt 2>/dev/null || echo 0)
Live validated: $(wc -l < live-params/validated.txt 2>/dev/null || echo 0)

[ALL LIVE ENDPOINTS]
All-live validated endpoints: $(wc -l < live-params/validated_all_endpoints.txt 2>/dev/null || echo 0)

[NUCLEI OUTPUTS]
$(ls nuclei-output 2>/dev/null | sed 's/^/- /' || true)

==============================================
FILES LOCATION:
- All endpoints: endpoints/all-endpoints.txt
- LinkFinder endpoints: endpoints/from-js.linkfinder.*
- GF patterns: gf-output/
- Validated params: live-params/validated.txt
- Validated ALL endpoints: live-params/validated_all_endpoints.txt
- Nuclei outputs: nuclei-output/
==============================================
EOF

cat REPORT.txt
echo
echo -e "${GREEN}[✓] Scan complete! Results saved in: $OUTPUT_DIR${NC}"
echo -e "${YELLOW}[*] Review REPORT.txt for summary${NC}"
echo -e "${BLUE}[*] Check folders for detailed results${NC}"
