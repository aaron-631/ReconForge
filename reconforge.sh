#!/bin/bash

# ==============================================================================
# FINAL RECONNAISSANCE SCRIPT (v19.2 - Enhanced Banner)
#
# Author: Aaron
# Date: 2025-08-06
#
# Description: A professional-grade, single-file reconnaissance script.
#              This version consolidates all prior features, ensuring robust
#              error handling, timeouts, and a complete summary report that
#              includes all collected data (Whois, Sitemap, etc.).
#
# Changelog (v19.2):
#     - ENHANCED: Banner visuals with a new color scheme and professional layout.
#     - MODIFIED: Author credit line for a more professional tone.
# ==============================================================================

# --- Graceful Cleanup on Exit ---
trap 'cleanup' INT
cleanup() {
    # Don't show message in silent mode
    if [ "$SILENT_MODE" = false ]; then
        log_warn "\nScript interrupted. Exiting cleanly."
    fi
    exit 130
}

# --- Configuration & Defaults ---
DEFAULT_DIR_WORDLIST_PATH="/usr/share/wordlists/dirb/common.txt"
DEFAULT_SUBDOMAIN_WORDLIST_PATH="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DEFAULT_TIMEOUT="30s" # Timeout for network tools (nmap, ffuf, curl, etc.)
USER_AGENTS=(
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
)
RANDOM_UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
SILENT_MODE=false

# --- Color & Logging Functions ---
log()        { [ "$SILENT_MODE" = false ] && echo -e "[\e[34m*\e[0m] \e[1m$1\e[0m"; }
log_success(){ [ "$SILENT_MODE" = false ] && echo -e "[\e[32m+\e[0m] \e[1m$1\e[0m"; }
log_error()  { [ "$SILENT_MODE" = false ] && echo -e "[\e[31m-\e[0m] \e[1m$1\e[0m" >&2; }
log_warn()   { [ "$SILENT_MODE" = false ] && echo -e "[\e[33m!\e[0m] \e[1m$1\e[0m"; }

# --- Banner Function ---
show_banner() {
    if [ "$SILENT_MODE" = false ]; then
        # Use a brighter color like bright cyan for better visibility
        local color='\e[96m'
        local nc='\e[0m' # No Color

        echo -e "${color}"
        figlet -f slant "ReconForge"
        echo -e "    +---------------------------------------+"
        echo -e "    |          Author: Aaron              |"
        echo -e "    |   Recon Script v19.2 (Enhanced)     |"
        echo -e "    +---------------------------------------+"
        echo -e "${nc}"
    fi
}


# --- Usage Information ---
show_usage() {
  echo "Usage: $0 -d <domain_or_ip> [OPTIONS]"
  echo ""
  echo "Required:"
  echo "  -d <domain_or_ip>      : The target domain or IP address."
  echo ""
  echo "Scan Modes (Choose one, default is Full):"
  echo "  -l                   : LITE scan (Fast service scan, no deep scripts)."
  echo "  -m                   : MINIMAL scan (Port discovery only)."
  echo ""
  echo "Options:"
  echo "  -h, --help           : Show this help message."
  echo "  -s                   : Enable subdomain enumeration."
  echo "  -w <path>            : Path to a custom wordlist for directory fuzzing."
  echo "  -sw <path>           : Path to a custom wordlist for subdomain fuzzing."
  echo "  --silent             : Suppress console output. All results are saved to files."
  echo "  --dry-run            : Preview all commands without executing them."
  exit 0
}

# --- Argument Parsing ---
SCAN_MODE="FULL"
DO_SUBDOMAIN_SCAN=false
DRY_RUN=false
DIR_WORDLIST="$DEFAULT_DIR_WORDLIST_PATH"
SUBDOMAIN_WORDLIST="$DEFAULT_SUBDOMAIN_WORDLIST_PATH"

while [[ "$1" != "" ]]; do
    case $1 in
        -d )                   shift; TARGET=$1 ;;
        -l )                   SCAN_MODE="LITE" ;;
        -m )                   SCAN_MODE="MINIMAL" ;;
        -s )                   DO_SUBDOMAIN_SCAN=true ;;
        -w )                   shift; DIR_WORDLIST=$1 ;;
        -sw )                  shift; SUBDOMAIN_WORDLIST=$1 ;;
        --silent )             SILENT_MODE=true ;;
        --dry-run )            DRY_RUN=true ;;
        -h | --help )          show_usage ;;
        * )                    log_error "Invalid option: $1"; show_usage; exit 1 ;;
    esac
    shift
done

# --- Validation & Setup ---
if [ -z "$TARGET" ]; then
  log_error "Target not provided. Use the -d flag."
  show_usage
  exit 1
fi

TARGET_CLEAN=$(echo "$TARGET" | tr '/:' '_')
DATE=$(date +"%Y-%m-%d_%H-%M")
OUTPUT_DIR="recon_results/${TARGET_CLEAN}-${DATE}"
LOG_FILE="$OUTPUT_DIR/scan.log"
# Convert timeout string (e.g., "30s") to seconds for tools that need it
TIMEOUT_SECONDS=${DEFAULT_TIMEOUT%s}

mkdir -p "$OUTPUT_DIR"/{nmap,web,passive}

# --- Core Functions ---
execute() {
    local is_fatal=false
    if [[ "$1" == "--fatal" ]]; then
        is_fatal=true
        shift
    fi

    local command_str="$*"
    log "Preparing to run: $command_str"
    if [ "$DRY_RUN" == true ]; then
        log_warn "DRY RUN: Command not executed."
        return 0
    fi

    echo "[$(date)] ==> $command_str" >> "$LOG_FILE"
    
    # Using eval to correctly handle complex commands with quotes and redirections
    if [ "$SILENT_MODE" = true ]; then
        eval "$command_str" &>> "$LOG_FILE"
    else
        eval "$command_str"
    fi
    
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Command failed with exit code $exit_code: $command_str"
        if [ "$is_fatal" = true ]; then
            log_error "This was a critical step. Aborting script."
            exit 1
        fi
    fi
    return $exit_code
}

check_dependencies() {
    log "Verifying required tools..."
    # xmllint is optional for pretty-printing, not a hard requirement.
    # Added figlet for the banner
    REQUIRED_TOOLS=(nmap rustscan ffuf whatweb getent tree ping curl whois jq pandoc openssl figlet)
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "'$tool' is required but not installed. Please install it."
            exit 1
        fi
    done
    log_success "All required tools are installed."
}

check_wordlists() {
    if [ ! -r "$DIR_WORDLIST" ]; then
        log_error "Directory wordlist not found or not readable: $DIR_WORDLIST"; exit 1
    fi
    if [ "$DO_SUBDOMAIN_SCAN" == true ] && [ ! -r "$SUBDOMAIN_WORDLIST" ]; then
        log_error "Subdomain wordlist not found or not readable: $SUBDOMAIN_WORDLIST"; exit 1
    fi
}

resolve_target() {
    log "Resolving IP for '$TARGET'..."
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        TARGET_IP="$TARGET"; IS_IP=true
    else
        TARGET_IP=$(getent hosts "$TARGET" | awk '{print $1}' | head -n 1); IS_IP=false
        if [ -z "$TARGET_IP" ]; then
            log_error "DNS resolution failed for '$TARGET'. Check network."; exit 1
        fi
    fi
    log_success "Target '$TARGET' resolved to IP: $TARGET_IP"
}

passive_enum() {
    if [ "$IS_IP" == true ]; then
        log "Target is an IP. Skipping passive whois lookup."; return
    fi
    log "Performing parsed whois lookup..."
    execute "whois \"$TARGET\" | grep -iE 'Registrant|Organization|Country|Domain Name|Registry Domain ID|Registrar|Creation Date|Updated Date|Expiration Date' > \"$OUTPUT_DIR/passive/whois_parsed.txt\""
}

port_scan() {
    log "Starting TCP port scan (Mode: $SCAN_MODE)..."
    local RUSTSCAN_ARGS=(-a "$TARGET_IP" --ulimit 5000 --timeout "$(($TIMEOUT_SECONDS * 1000))")
    local NMAP_ARGS
    local nmap_command

    if [ "$SCAN_MODE" == "MINIMAL" ]; then
        log_warn "MINIMAL MODE: Discovering open ports only."
        nmap_command="rustscan ${RUSTSCAN_ARGS[*]} -- -oA \"$OUTPUT_DIR/nmap/tcp_scan\" -T4 -Pn --host-timeout $DEFAULT_TIMEOUT"
    else
        NMAP_ARGS=$([ "$SCAN_MODE" == "LITE" ] && echo "-sV -Pn -T4" || echo "-sV -sC -O -Pn -T4")
        log "$([ "$SCAN_MODE" == "LITE" ] && echo 'LITE MODE: Running fast service scan.' || echo 'FULL MODE: Running comprehensive scan.')"
        nmap_command="rustscan ${RUSTSCAN_ARGS[*]} -- $NMAP_ARGS --host-timeout $DEFAULT_TIMEOUT -oA \"$OUTPUT_DIR/nmap/tcp_scan\""
    fi
    
    execute --fatal "$nmap_command"
    log_success "TCP port scan complete."
}

extract_ports() {
    log "Extracting open ports..."
    if [ -f "$OUTPUT_DIR/nmap/tcp_scan.gnmap" ]; then
        OPEN_PORTS=$(grep -o '[0-9]*/open' "$OUTPUT_DIR/nmap/tcp_scan.gnmap" | awk -F'/' '{print $1}' | tr '\n' ',' | sed 's/,$//')
    fi

    if [ -z "$OPEN_PORTS" ]; then
        log_warn "No open TCP ports were found."
    else
        log_success "Open Ports Detected: $OPEN_PORTS"
    fi
}

web_enum() {
    log "Starting intelligent web enumeration..."
    local COMMON_WEB_PORTS=(80 443 8000 8080 8443)
    local found_web_ports=()

    for port in "${COMMON_WEB_PORTS[@]}"; do
        if [[ ",$OPEN_PORTS," == *",$port,"* ]]; then
            found_web_ports+=("$port")
        fi
    done

    if [ ${#found_web_ports[@]} -eq 0 ]; then
        log "No common web ports found. Skipping web enumeration."
        return
    fi

    for port in "${found_web_ports[@]}"; do
        local SCHEME="http"
        [[ "$port" == "443" || "$port" == "8443" ]] && SCHEME="https"

        local BASE_URL="${SCHEME}://${TARGET}:${port}"
        [[ "$port" == "80" || "$port" == "443" ]] && BASE_URL="${SCHEME}://${TARGET}"

        local WEB_PORT_DIR="$OUTPUT_DIR/web/port_${port}"
        mkdir -p "$WEB_PORT_DIR"

        log "--- Enumerating web service on $BASE_URL ---"

        log "Checking for robots.txt and sitemap.xml..."
        execute "curl --max-time $TIMEOUT_SECONDS -s -k -L -A \"$RANDOM_UA\" \"${BASE_URL}/robots.txt\" -o \"${WEB_PORT_DIR}/robots.txt\""
        execute "curl --max-time $TIMEOUT_SECONDS -s -k -L -A \"$RANDOM_UA\" \"${BASE_URL}/sitemap.xml\" -o \"${WEB_PORT_DIR}/sitemap.xml\""

        log "Searching for web technologies with WhatWeb..."
        execute "whatweb --user-agent \"$RANDOM_UA\" \"$BASE_URL\" > \"$WEB_PORT_DIR/whatweb.txt\""

        log "Calibrating FFUF for noise detection..."
        local FFUF_FILTER_ARGS=()
        if [ "$DRY_RUN" == false ]; then
            local random_path
            random_path=$(openssl rand -hex 8)
            local junk_response
            junk_response=$(curl --max-time $TIMEOUT_SECONDS -s -k -L -w "\n%{http_code}" -A "$RANDOM_UA" "${BASE_URL}/${random_path}")
            local junk_code
            junk_code=$(echo "$junk_response" | tail -n1)
            
            if [ -n "$junk_code" ] && [ "$junk_code" -ne 404 ]; then
                 log_warn "Non-404 code '$junk_code' returned for random path. Configuring FFUF filters."
                 local junk_body
                 junk_body=$(echo "$junk_response" | sed '$d')
                 local junk_size
                 junk_size=$(echo -n "$junk_body" | wc -c)
                 local junk_words
                 junk_words=$(echo -n "$junk_body" | wc -w)
                 FFUF_FILTER_ARGS=(-fc "$junk_code") # Note: array assignment
                 if [ "$junk_size" -gt 0 ]; then FFUF_FILTER_ARGS+=(-fs "$junk_size"); fi
                 if [ "$junk_words" -gt 0 ]; then FFUF_FILTER_ARGS+=(-fw "$junk_words"); fi
                 log_success "FFUF filters configured: ${FFUF_FILTER_ARGS[*]}"
            else
                 log "Standard 404 behavior detected. Filtering 404s."
                 FFUF_FILTER_ARGS=(-fc 404)
            fi
        fi

        log "Searching for directories with FFUF on $BASE_URL..."
        execute "ffuf -timeout $TIMEOUT_SECONDS -w \"$DIR_WORDLIST\" -u \"${BASE_URL}/FUZZ\" -t 40 \
            -H 'User-Agent: $RANDOM_UA' \
            ${FFUF_FILTER_ARGS[*]} \
            -of json -o \"$WEB_PORT_DIR/ffuf_dirs.json\""
    done
    log_success "Web enumeration complete."
}

subdomain_enum() {
    if [ "$IS_IP" == true ]; then
        log "Target is an IP. Skipping subdomain enumeration."; return
    fi
    log "Starting subdomain enumeration..."

    log "Performing DNS wildcard check..."
    local random_sub="gemini-test-$(date +%s)"
    # Check if a random subdomain resolves (non-zero response code from curl indicates it does)
    if [ "$DRY_RUN" == false ] && [[ $(curl --max-time $TIMEOUT_SECONDS -s -o /dev/null -w "%{http_code}" "http://${random_sub}.${TARGET}") -ne 000 ]]; then
        log_error "Wildcard DNS detected for *.$TARGET. Skipping subdomain FFUF scan."; return
    else
        log_success "No DNS wildcard detected. Proceeding with scan."
    fi

    log "Enumerating subdomains via HTTP..."
    execute "ffuf -timeout $TIMEOUT_SECONDS -w \"$SUBDOMAIN_WORDLIST\" -u \"http://FUZZ.$TARGET\" -H 'User-Agent: $RANDOM_UA' \
        -mc 200,204,301,302,307,403 -of json -o \"$OUTPUT_DIR/web/ffuf_subdomains_http.json\""

    if echo "$OPEN_PORTS" | grep -q "443"; then
        log "Port 443 is open, enumerating subdomains via HTTPS..."
        execute "ffuf -timeout $TIMEOUT_SECONDS -w \"$SUBDOMAIN_WORDLIST\" -u \"https://FUZZ.$TARGET\" -H 'User-Agent: $RANDOM_UA' \
            -mc 200,204,301,302,307,403 -of json -o \"$OUTPUT_DIR/web/ffuf_subdomains_https.json\""
    fi
    log_success "Subdomain enumeration complete."
}

generate_summary_report() {
    log "Generating summary reports (MD and HTML)..."
    local SUMMARY_MD="$OUTPUT_DIR/SUMMARY.md"
    local REPORT_HTML="$OUTPUT_DIR/REPORT.html"

    {
        echo "# Reconnaissance Report for: $TARGET"
        echo "**Generated on:** $(date)"
        echo "**IP Address:** $TARGET_IP"
        echo "***"

        echo "## Open Ports Summary"
        if [ -n "$OPEN_PORTS" ]; then
            echo '```'
            echo "$OPEN_PORTS" | sed 's/,/\n/g'
            echo '```'
        else
            echo "_No open TCP ports found._"
        fi
        
        echo -e "\n## Passive Enumeration (Whois)"
        local whois_file="$OUTPUT_DIR/passive/whois_parsed.txt"
        if [ -s "$whois_file" ]; then
            echo '```'
            cat "$whois_file"
            echo '```'
        else
            echo "_Whois scan skipped for IP or produced no results._"
        fi

        if [ -d "$OUTPUT_DIR/web" ]; then
            for port_dir in "$OUTPUT_DIR"/web/port_*; do
                if [ ! -d "$port_dir" ]; then continue; fi
                
                port_num=$(basename "$port_dir" | cut -d'_' -f2)
                echo -e "\n***\n"
                echo "## Web Service Analysis: Port $port_num"

                if [ -s "$port_dir/whatweb.txt" ]; then
                    echo "### Technology Stack"
                    echo '```'
                    sed 's/, /,/g' "$port_dir/whatweb.txt" | tr ',' '\n'
                    echo '```'
                else
                     echo "### Technology Stack"
                     echo "_No technology information discovered._"
                fi

                if [ -s "$port_dir/robots.txt" ]; then
                    echo "### robots.txt Contents"
                    echo '```'
                    cat "$port_dir/robots.txt"
                    echo '```'
                else
                    echo "### robots.txt Contents"
                    echo "_File not found or is empty._"
                fi

                if [ -s "$port_dir/sitemap.xml" ]; then
                    echo "### sitemap.xml Contents"
                    echo '```xml'
                    # Use xmllint for pretty-printing if available, otherwise just cat
                    if command -v xmllint &> /dev/null; then
                        xmllint --format "$port_dir/sitemap.xml" 2>/dev/null || cat "$port_dir/sitemap.xml"
                    else
                        cat "$port_dir/sitemap.xml"
                    fi
                    echo '```'
                else
                    echo "### sitemap.xml Contents"
                    echo "_File not found or is empty._"
                fi

                if [ -s "$port_dir/ffuf_dirs.json" ]; then
                    local dir_count
                    dir_count=$(jq '.results | length' "$port_dir/ffuf_dirs.json")
                    echo "### Discovered Directories/Files ($dir_count found)"
                    if [ "$dir_count" -gt 0 ]; then
                        echo '```'
                        jq -r '.results[] | .url' "$port_dir/ffuf_dirs.json"
                        echo '```'
                    else
                        echo "_No directories or files discovered._"
                    fi
                else
                    echo "### Discovered Directories/Files"
                    echo "_Directory scan did not run or produced no results._"
                fi
            done
        fi

        echo -e "\n***\n"
        echo "## Subdomain Enumeration"
        local http_json="$OUTPUT_DIR/web/ffuf_subdomains_http.json"
        local https_json="$OUTPUT_DIR/web/ffuf_subdomains_https.json"
        if [ -s "$http_json" ] || [ -s "$https_json" ]; then
             local sub_list
             sub_list=$( (jq -r '.results[] | .url' "$http_json" 2>/dev/null; \
                         jq -r '.results[] | .url' "$https_json" 2>/dev/null) | sort -u )
             local sub_count
             sub_count=$(echo "$sub_list" | wc -l)
             echo "### Discovered Subdomains ($sub_count unique found)"
             echo '```'
             echo "$sub_list"
             echo '```'
        else
             echo "_No subdomains discovered or scan not performed._"
        fi
    } > "$SUMMARY_MD"

    if command -v pandoc &> /dev/null && [ "$DRY_RUN" == false ]; then
        pandoc "$SUMMARY_MD" -o "$REPORT_HTML" --metadata title="Recon Report: $TARGET" --standalone --toc --css=https://cdn.jsdelivr.net/npm/water.css@2/out/dark.css
        log_success "HTML report created at $REPORT_HTML"
    else
        log_warn "Pandoc not found or in dry-run. Skipping HTML report generation."
    fi
}

# --- Main Execution Flow ---
main() {
    [ "$SILENT_MODE" = false ] && clear
    
    check_dependencies
    show_banner

    log "Target: $TARGET | Mode: $SCAN_MODE"
    if [ "$DRY_RUN" == true ]; then log_warn "DRY RUN MODE IS ENABLED"; fi
    if [ "$SILENT_MODE" == true ]; then log_warn "SILENT MODE IS ENABLED"; fi
    log "------------------------------------------------------------"

    check_wordlists
    resolve_target

    passive_enum
    port_scan

    extract_ports

    if [ "$SCAN_MODE" != "MINIMAL" ]; then
        web_enum
    fi

    if [ "$DO_SUBDOMAIN_SCAN" == true ]; then
        subdomain_enum
    fi

    log "------------------------------------------------------------"
    generate_summary_report
    log_success "Reconnaissance mission complete! 🚀"
    log "All output saved to: $OUTPUT_DIR"
    log "View the HTML report at: file://${OUTPUT_DIR}/REPORT.html"
    log "A full command log is available at: ${LOG_FILE}"
    execute "tree \"$OUTPUT_DIR\""
}

main "$@"
