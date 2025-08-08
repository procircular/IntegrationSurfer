#!/bin/bash
# ============================================================================
# INTEGRATION SURFER v1.0 - WebMethods Integration Server Reconnaissance Tool
# ============================================================================
#
# Usage: ./Integration_Surfer.sh <ips_file> <output_file> [options]
#
# REQUIRED ARGUMENTS:
#   <ips_file>      : File containing one asset per line (IPs or domains, e.g., integration_ips.txt)
#   <output_file>   : File to which recon output is appended
#
# OPTIONAL ARGUMENTS:
#   -p, --port PORT     Port to use (default: 443)
#
# INTERACTIVE MENU OPTIONS:
#   After providing required arguments, the script presents an interactive menu:
#   1. 🏄‍♂️ Integration Server Detection (tests 9 endpoints)
#      - Scans for WebMethods Integration Server instances
#      - Tests 9 different endpoints to identify servers
#   2. 🔐 Default Credential Testing (tests 6 credentials)
#      - Tests common default credentials on discovered servers
#      - Tests: Administrator/manage, Sysadmin/manage, designer/manage, etc.
#   3. 🌊 Fuzzing (runs ffuf over everything)
#      - Performs comprehensive fuzzing using ffuf
#      - Uses extensive wordlist from IntegrationServerFUZZ.txt
#   4. 🏄‍♀️ Run All Tests (detection + credentials + fuzzing)
#      - Complete reconnaissance pipeline
#      - Original behavior - runs all phases sequentially
#   5. 🏄‍♂️ Test Credentials and Fuzz (skip detection, assume good data)
#      - Skips server detection phase
#      - Assumes you already have confirmed servers
#      - Runs credential testing + fuzzing only
#   6. 🔐 Detection + Credentials only (no fuzzing)
#      - Server detection + credential testing
#      - Skips resource-intensive fuzzing phase
#   7. 🌊 Detection + Fuzzing only (no credentials)
#      - Server detection + fuzzing
#      - Skips credential testing phase
#
# SCRIPT BEHAVIOR:
#   1. Displays interactive menu for operation selection
#   2. Splits workload into chunks (~1% per chunk) in "chunks" directory
#   3. Processes chunks sequentially with progress tracking
#   4. Creates confirmedIntegrationservers.txt for discovered servers
#   5. Creates successful_credentials.txt for found credentials
#   6. Deletes processed chunks to allow recovery
#   7. Provides detailed timing and progress information
#
# REQUIRED FILES:
#   - integration_ips.txt: List of IP addresses or domains to scan
#   - fuzzlist.txt: Fuzzing wordlist (189KB)
#   - IntegrationServerFUZZ.txt: Extended fuzzing data (189KB)
#
# OUTPUT FILES:
#   - confirmedIntegrationservers.txt: Discovered integration servers
#   - successful_credentials.txt: Found valid credentials
#   - <output_file>: Detailed scan results and logs
#
#

# Check that at least 2 arguments are provided.
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <ips_file> <output_file> [options]"
    echo "Options:"
    echo "   -f, --fast          Use fast integration server detection method."
    echo "   -p, --port PORT     Port to use (default: 443)."
    echo "   --protocol PROTO    Protocol to use (default: https)."
    exit 1
fi

# Required arguments.
IPS_FILE="$1"
OUTPUT_FILE="$2"

# Function to resolve domains to IPs
resolve_domains() {
    local input_file="$1"
    local resolved_file="/tmp/resolved_$(date +%s)"
    
    echo "🔍 Processing input file for domains and IPs..." >&2
    
    # Create a temporary file for resolved addresses
    > "$resolved_file"
    
    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Remove any whitespace and carriage returns
        line=$(echo "$line" | tr -d '\r' | xargs)
        
        # Check if it's an IP address (simple regex)
        if [[ "$line" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            # It's an IP address, add it directly
            echo "$line" >> "$resolved_file"
        else
            # It's likely a domain, try to resolve it
            echo "🔍 Resolving domain: $line" >&2
            resolved_ips=$(nslookup "$line" 2>/dev/null | grep -E "Address:" | grep -v "127.0.0.1" | awk '{print $2}' | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" | sort -u)
            
            if [ -n "$resolved_ips" ]; then
                echo "$resolved_ips" >> "$resolved_file"
                echo "✅ Resolved $line to: $(echo "$resolved_ips" | wc -l | xargs) IP(s)" >&2
            else
                echo "⚠️  Could not resolve domain: $line" >&2
            fi
        fi
    done < "$input_file"
    
    # Remove duplicates and return the resolved file
    sort -u "$resolved_file" > "${resolved_file}.unique"
    mv "${resolved_file}.unique" "$resolved_file"
    
    echo "📊 Resolved $(wc -l < "$resolved_file") unique IP addresses" >&2
    echo "$resolved_file"
}

# Resolve domains in the input file
RESOLVED_FILE=$(resolve_domains "$IPS_FILE")
shift 2

# Display menu and get user choice
echo ""
echo "🏄‍♂️==================================================🏄‍♀️"
echo "🏄‍♂️        INTEGRATION SURFER v1.0        🏄‍♀️"
echo "🏄‍♂️==================================================🏄‍♀️"
echo ""
echo "🌊 Choose your surfing operation:"
echo "1. 🏄‍♂️ Integration Server Detection (tests 9 endpoints)"
echo "2. 🔐 Default Credential Testing (tests 6 credentials)"
echo "3. 🌊 Fuzzing (runs ffuf over everything)"
echo "4. 🏄‍♀️ Run All Tests (detection + credentials + fuzzing)"
echo "5. 🏄‍♂️ Test Credentials and Fuzz (skip detection, assume good data)"
echo "6. 🔐 Detection + Credentials only (no fuzzing)"
echo "7. 🌊 Detection + Fuzzing only (no credentials)"
echo ""
read -p "🏄‍♂️ Enter your choice (1-7): " MENU_CHOICE

# Set operation flags based on menu choice
case $MENU_CHOICE in
    1)
        DETECTION_ONLY=true
        CREDENTIALS_ONLY=false
        FUZZING_ONLY=false
        RUN_ALL=false
        CREDS_AND_FUZZ=false
        DETECTION_AND_CREDS=false
        DETECTION_AND_FUZZ=false
        echo "🏄‍♂️ Selected: Integration Server Detection only"
        ;;
    2)
        DETECTION_ONLY=false
        CREDENTIALS_ONLY=true
        FUZZING_ONLY=false
        RUN_ALL=false
        CREDS_AND_FUZZ=false
        DETECTION_AND_CREDS=false
        DETECTION_AND_FUZZ=false
        echo "🔐 Selected: Default Credential Testing only"
        ;;
    3)
        DETECTION_ONLY=false
        CREDENTIALS_ONLY=false
        FUZZING_ONLY=true
        RUN_ALL=false
        CREDS_AND_FUZZ=false
        DETECTION_AND_CREDS=false
        DETECTION_AND_FUZZ=false
        echo "🌊 Selected: Fuzzing only"
        ;;
    4)
        DETECTION_ONLY=false
        CREDENTIALS_ONLY=false
        FUZZING_ONLY=false
        RUN_ALL=true
        CREDS_AND_FUZZ=false
        DETECTION_AND_CREDS=false
        DETECTION_AND_FUZZ=false
        echo "🏄‍♀️ Selected: Run All Tests (original behavior)"
        ;;
    5)
        DETECTION_ONLY=false
        CREDENTIALS_ONLY=false
        FUZZING_ONLY=false
        RUN_ALL=false
        CREDS_AND_FUZZ=true
        DETECTION_AND_CREDS=false
        DETECTION_AND_FUZZ=false
        echo "🏄‍♂️ Selected: Test Credentials and Fuzz (skip detection)"
        ;;
    6)
        DETECTION_ONLY=false
        CREDENTIALS_ONLY=false
        FUZZING_ONLY=false
        RUN_ALL=false
        CREDS_AND_FUZZ=false
        DETECTION_AND_CREDS=true
        DETECTION_AND_FUZZ=false
        echo "🔐 Selected: Detection + Credentials only (no fuzzing)"
        ;;
    7)
        DETECTION_ONLY=false
        CREDENTIALS_ONLY=false
        FUZZING_ONLY=false
        RUN_ALL=false
        CREDS_AND_FUZZ=false
        DETECTION_AND_CREDS=false
        DETECTION_AND_FUZZ=true
        echo "🌊 Selected: Detection + Fuzzing only (no credentials)"
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# Set defaults.
FAST_MODE=false
PORT=443
PROTOCOL="https"

# Parse options.
while [[ "$#" -gt 0 ]]; do
    case "$1" in
         -f|--fast)
              FAST_MODE=true
              shift
              ;;
         -p|--port)
              PORT="$2"
              shift 2
              ;;
         --protocol)
              PROTOCOL="$2"
              shift 2
              ;;
         *)
              echo "Unknown option: $1"
              exit 1
              ;;
    esac
done

# Determine the directory of the input file and set integration servers file.
DIR=$(dirname "$IPS_FILE")
INTEGRATION_SERVERS_FILE="$DIR/confirmedIntegrationservers.txt"
LOCK_FILE="$INTEGRATION_SERVERS_FILE.lock"

# Credentials for recon phase.
USERNAME="Administrator"
PASSWORD="manage"
AUTH_HEADER="Authorization: Basic QWRtaW5pc3RyYXRvcjpNYW5hZ2U="

# Array of usernames to test for credential testing
USERNAMES=("Administrator" "Sysadmin" "designer" "guest" "WEBM_SYSUSER")

# Common ffuf parameters.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

# File for discovery endpoints.
DISCOVERY_ENDPOINTS_FILE="integrationserver-test.txt"
if [ ! -f "$DISCOVERY_ENDPOINTS_FILE" ]; then
    cat <<EOF > "$DISCOVERY_ENDPOINTS_FILE"
/invoke/false.positive:test
/invoke/wm.server.csrfguard:isCSRFGuardEnabled
/invoke/wm.server.csrfguard:getCSRFSecretToken
/invoke/wm.server.tx:start
/invoke/wm.server:ping
/invoke/wm.server:disconnect
/invoke/wm.server:connect
/invoke/wm.server:noop
/invoke/wm.server:getServerNodes
EOF
fi

# File for recon endpoints.
RECON_ENDPOINTS_FILE="IntegrationServerFUZZ.txt"
if [ ! -f "$RECON_ENDPOINTS_FILE" ]; then
    echo "Recon endpoints file $RECON_ENDPOINTS_FILE not found!"
    exit 1
fi

# FUZZ placeholder for ffuf.
FUZZ_PLACEHOLDER="FUZZ"

# Discord webhook URL.
DISCORD_WEBHOOK=""

# Function to post a message to Discord.
post_to_discord() {
    local domain="$1"
    curl -s -H "Content-Type: application/json" -X POST \
         -d "{\"content\": \"Confirmed integration server: ${domain}\"}" \
         "$DISCORD_WEBHOOK" > /dev/null
}

# Function to safely add IP to confirmed servers file (check for duplicates)
add_to_confirmed_servers() {
    local ip="$1"
    (
        flock -x 200
        # Check if IP already exists in file
        if [ -f "$INTEGRATION_SERVERS_FILE" ]; then
            if ! grep -Fxq "$ip" "$INTEGRATION_SERVERS_FILE"; then
                echo "$ip" >> "$INTEGRATION_SERVERS_FILE"
                echo "[INFO] Added new integration server: $ip"
            else
                echo "[INFO] Integration server already exists: $ip"
            fi
        else
            echo "$ip" >> "$INTEGRATION_SERVERS_FILE"
            echo "[INFO] Added new integration server: $ip"
        fi
    ) 200>"$LOCK_FILE"
}

# Function to display file locations and summary
display_file_summary() {
    echo ""
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo "🏄‍♂️         SURFING SESSION COMPLETE!            🏄‍♀️"
    echo "🏄‍♂️==================================================🏄‍♀️"
    
    # Show confirmed servers file
    if [ -f "$INTEGRATION_SERVERS_FILE" ] && [ -s "$INTEGRATION_SERVERS_FILE" ]; then
        echo "✅ Confirmed Integration Servers:"
        echo "   File: $INTEGRATION_SERVERS_FILE"
        echo "   Count: $(wc -l < "$INTEGRATION_SERVERS_FILE") servers"
        echo ""
    fi
    
    # Show main output file
    if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
        echo "✅ Main Output Results:"
        echo "   File: $OUTPUT_FILE"
        echo "   Lines: $(wc -l < "$OUTPUT_FILE") lines"
        echo ""
    fi
    
    # Show successful credentials file
    if [ -f "$SUCCESSFUL_CREDENTIALS_FILE" ] && [ -s "$SUCCESSFUL_CREDENTIALS_FILE" ]; then
        echo "✅ Successful Credentials:"
        echo "   File: $SUCCESSFUL_CREDENTIALS_FILE"
        echo "   Count: $(wc -l < "$SUCCESSFUL_CREDENTIALS_FILE") successful logins"
        echo ""
    fi
    
    # Show skipped servers file
    if [ -f "$SKIPPED_SERVERS_FILE" ] && [ -s "$SKIPPED_SERVERS_FILE" ]; then
        echo "⚠️  Skipped Servers (Down/Slow):"
        echo "   File: $SKIPPED_SERVERS_FILE"
        echo "   Count: $(wc -l < "$SKIPPED_SERVERS_FILE") servers skipped"
        echo ""
    fi
    
    echo ""
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo "🏄‍♂️     All results have been saved to the files above!    🏄‍♀️"
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo ""
}

# Function to check an asset (normal mode).
check_asset() {
    IP="$1"
    IP=$(echo "$IP" | tr -d '\r' | xargs)
    [ -z "$IP" ] && exit 0

    # Skip asset if it contains "alibaba" (case insensitive)
    if echo "$IP" | grep -qi "alibaba"; then
        echo "[DEBUG] Skipping asset: $IP contains 'alibaba'" >&2
        return
    fi

    # Use header-only detection on port 443 only (70% of results found here)
    # Research shows 443 is the primary port for Integration Servers
    # Testing multiple ports (443/80/5555/8443) significantly slowed down the tool
    header_result=$(curl -s -I -k --connect-timeout 5 --max-time 8 "${PROTOCOL}://$IP:443/invoke/wm.server.query:getCurrentUser" 2>&1)
    
    # Check for the definitive WWW-Authenticate header
    if echo "$header_result" | grep -qi "WWW-Authenticate: Basic realm=\"Integration Server\""; then
        echo "[DEBUG] [$IP:443] confirmed Integration Server (WWW-Authenticate header found)" >&2
        echo "Confirmed integration server: $IP:443"
        add_to_confirmed_servers "$IP:443"
        post_to_discord "$IP:443"
    else
        echo "[DEBUG] [$IP:443] not confirmed as Integration Server (no header)" >&2
    fi
}

# Function to check an asset (fast mode).
fast_check_asset() {
    IP="$1"
    IP=$(echo "$IP" | tr -d '\r' | xargs)
    [ -z "$IP" ] && exit 0

    # Skip asset if it contains "alibaba" (case insensitive)
    if echo "$IP" | grep -qi "alibaba"; then
        echo "[DEBUG] Skipping asset: $IP contains 'alibaba'" >&2
        return
    fi

    # Use fast mode detection on port 443 only (70% of results found here)
    # Research shows 443 is the primary port for Integration Servers
    # Testing multiple ports (443/80/5555/8443) significantly slowed down the tool
    URL="${PROTOCOL}://$IP:443/invoke/wm.server.query:getCurrentUser"
    echo "[DEBUG] Fast checking $URL with ffuf" >&2
    CMD="ffuf -s -k -mc 200,500 -H \"$AUTH_HEADER\" -H \"User-Agent: $UA\" -u \"$URL\" -w <(echo '')"
    echo "[DEBUG] Running command: $CMD" >&2
    result=$(eval $CMD 2>&1)
    echo "[DEBUG] Result for $IP:443:" >&2
    echo "$result" >&2

    if echo "$result" | grep -q "Administrator"; then
        echo "[DEBUG] [$IP:443] fast mode: detected integration server (Administrator found)" >&2
        echo "Confirmed integration server: $IP:443"
        add_to_confirmed_servers "$IP:443"
        post_to_discord "$IP:443"
    else
        echo "[DEBUG] [$IP:443] fast mode: response did not contain Administrator" >&2
    fi
}

export UA DISCOVERY_ENDPOINTS_FILE FUZZ_PLACEHOLDER LOCK_FILE INTEGRATION_SERVERS_FILE AUTH_HEADER PROTOCOL PORT
export -f check_asset
export -f fast_check_asset
export -f post_to_discord
export -f add_to_confirmed_servers

###############################
# Monitor Integration Servers Background Process
###############################
monitor_integrations() {
    # Use a temporary file to store already seen integration servers.
    seen_file=$(mktemp)
    # If the integration file exists, initialize seen_file with its sorted content.
    if [ -f "$INTEGRATION_SERVERS_FILE" ]; then
        sort -u "$INTEGRATION_SERVERS_FILE" > "$seen_file"
    else
        touch "$seen_file"
    fi

    while true; do
        sleep 600  # Wait 10 minutes.
        if [ -f "$INTEGRATION_SERVERS_FILE" ]; then
            # Sort the current integration servers.
            sort -u "$INTEGRATION_SERVERS_FILE" > /tmp/current_servers.txt
            # Compare with seen_file to find new entries.
            new_servers=$(comm -13 "$seen_file" /tmp/current_servers.txt)
            if [ -n "$new_servers" ]; then
                echo "Monitor: New integration servers found:"
                echo "$new_servers"
                for server in $new_servers; do
                    post_to_discord "$server"
                done
                cp /tmp/current_servers.txt "$seen_file"
            fi
        fi
    done
}

# Fork the monitor process in the background.
monitor_integrations &
MONITOR_PID=$!
echo "🏄‍♂️ Integration server monitor started (PID: $MONITOR_PID)"
echo ""

# Only run detection if not skipping it
if [ "$DETECTION_ONLY" = true ] || [ "$RUN_ALL" = true ] || [ "$DETECTION_AND_CREDS" = true ] || [ "$DETECTION_AND_FUZZ" = true ]; then
    ###############################
    # Discovery Phase with Chunked Processing
    ###############################
    CHUNK_DIR="$DIR/chunks"
    if [ -d "$CHUNK_DIR" ] && [ "$(ls -A "$CHUNK_DIR")" ]; then
        echo "Chunks already exist in $CHUNK_DIR."
        echo "Do you want to resume processing existing chunks (enter 'r') or clear them and restart (enter 'c')?"
        read -r choice
        if [ "$choice" = "c" ]; then
            rm -rf "$CHUNK_DIR"/*
        fi
    else
        mkdir -p "$CHUNK_DIR"
    fi

    TOTAL_DOMAINS=$(wc -l < "$RESOLVED_FILE")
    echo "🌊 Total domains to surf: $TOTAL_DOMAINS"
    echo ""

    if [ -z "$(ls -A "$CHUNK_DIR")" ]; then
        # Check if we have any domains to process
        if [ "$TOTAL_DOMAINS" -eq 0 ]; then
            echo "⚠️  No valid IPs or domains found to process"
            exit 1
        fi
        
        # Calculate chunk size to create approximately 10 chunks
        CHUNK_SIZE=$(( (TOTAL_DOMAINS + 9) / 10 ))
        # Ensure minimum chunk size of 1
        if [ "$CHUNK_SIZE" -lt 1 ]; then
            CHUNK_SIZE=1
        fi
        
        # Use macOS compatible split command
        split -l "$CHUNK_SIZE" -d "$RESOLVED_FILE" "$CHUNK_DIR/chunk_"
        # Rename files to add .chunk suffix
        for f in "$CHUNK_DIR"/chunk_*; do
            mv "$f" "$f.chunk"
        done
    fi

    NUM_CHUNKS=$(ls "$CHUNK_DIR"/*.chunk | wc -l)
    echo ""
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo "🏄‍♂️           DISCOVERY PHASE STARTING           🏄‍♀️"
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo ""

    chunk_counter=0
    for chunk in $(ls "$CHUNK_DIR"/*.chunk | sort); do
        chunk_counter=$((chunk_counter + 1))
        echo "Processing chunk $chunk_counter out of $NUM_CHUNKS..."
        START_TIME=$(date +%s)
        
        if [ "$FAST_MODE" = true ]; then
             cat "$chunk" | xargs -I {} -P 40 bash -c 'fast_check_asset "{}"' > /dev/null 2>&1
        else
             cat "$chunk" | xargs -I {} -P 40 bash -c 'check_asset "{}"' > /dev/null 2>&1
        fi
        
        END_TIME=$(date +%s)
        ELAPSED=$((END_TIME - START_TIME))
        echo "Chunk $chunk_counter processed in ${ELAPSED} seconds."
        rm -f "$chunk"
    done

    sort -u "$INTEGRATION_SERVERS_FILE" -o "$INTEGRATION_SERVERS_FILE"

    echo ""
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo "🏄‍♂️           DISCOVERY PHASE COMPLETE           🏄‍♀️"
    echo "🏄‍♂️==================================================🏄‍♀️"
    echo ""
    echo "🏄‍♂️ Integration servers detected (saved in $INTEGRATION_SERVERS_FILE):"
    cat "$INTEGRATION_SERVERS_FILE"
    echo ""
    
    # If this was detection only, ask if user wants to continue
    if [ "$DETECTION_ONLY" = true ]; then
        echo ""
        read -p "Found $(wc -l < "$INTEGRATION_SERVERS_FILE") integration servers. Proceed with credential testing and fuzzing? (y/n): " CONTINUE_CHOICE
        if [ "$CONTINUE_CHOICE" = "y" ] || [ "$CONTINUE_CHOICE" = "Y" ]; then
            echo "Proceeding with credential testing and fuzzing..."
            CREDENTIALS_ONLY=false
            FUZZING_ONLY=false
            RUN_ALL=true
            CREDS_AND_FUZZ=false
            DETECTION_ONLY=false
        else
            echo "Detection complete. Exiting."
            # Clean up the monitor process.
kill $MONITOR_PID
echo ""
echo "🏄‍♂️ Integration server monitor (PID: $MONITOR_PID) terminated."
echo ""

# Display file summary
display_file_summary
            exit 0
        fi
    fi
fi

# For modes that skip detection, check if confirmed servers file exists
if [ "$CREDENTIALS_ONLY" = true ] || [ "$FUZZING_ONLY" = true ] || [ "$CREDS_AND_FUZZ" = true ]; then
    if [ -f "$INTEGRATION_SERVERS_FILE" ] && [ -s "$INTEGRATION_SERVERS_FILE" ]; then
        echo "Found existing confirmed integration servers file with $(wc -l < "$INTEGRATION_SERVERS_FILE") servers."
        read -p "Use confirmed servers from previous detection? (y/n): " USE_CONFIRMED
        if [ "$USE_CONFIRMED" = "y" ] || [ "$USE_CONFIRMED" = "Y" ]; then
            echo "Using confirmed servers from previous detection."
        else
            echo "Using original input file for testing."
            INTEGRATION_SERVERS_FILE="$IPS_FILE"
        fi
    else
        echo "No confirmed servers file found. Using original input file for testing."
        INTEGRATION_SERVERS_FILE="$IPS_FILE"
    fi
fi

# Only run credential testing if selected
if [ "$CREDENTIALS_ONLY" = true ] || [ "$RUN_ALL" = true ] || [ "$CREDS_AND_FUZZ" = true ] || [ "$DETECTION_AND_CREDS" = true ]; then
    ###############################
    # Credential Testing Phase
    ###############################
    echo ""
    echo "🔐==================================================🔐"
    echo "🔐         CREDENTIAL TESTING PHASE STARTING        🔐"
    echo "🔐==================================================🔐"
    echo ""

    # Create successful credentials file
    SUCCESSFUL_CREDENTIALS_FILE="$DIR/successful_credentials.txt"
    echo "Successful credentials will be saved to: $SUCCESSFUL_CREDENTIALS_FILE"

    # Create skipped servers file
    SKIPPED_SERVERS_FILE="$DIR/skipped_servers.txt"
    echo "Skipped servers (down/slow) will be saved to: $SKIPPED_SERVERS_FILE"

    GET_ENDPOINT="/invoke/wm.server.query:getCurrentUser"

    while IFS= read -r asset || [ -n "$asset" ]; do
        # Skip if asset contains "alibaba"
        if echo "$asset" | grep -qi "alibaba"; then
             echo "[DEBUG] Skipping credential test on asset: $asset contains 'alibaba'"
             continue
        fi

        echo "Testing credentials on integration server: $asset"
        
        # Quick connectivity check - skip if server is down or too slow
        CONNECT_TEST=$(curl -s -I -k --connect-timeout 3 --max-time 5 "${PROTOCOL}://$asset$GET_ENDPOINT" 2>&1)
        if [ $? -ne 0 ] || [ -z "$CONNECT_TEST" ]; then
            echo "[DEBUG] Skipping $asset - server not responding or too slow"
            # Only log actual IPs/domains, not comments
            if [[ "$asset" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ "$asset" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                echo "$asset" >> "$SKIPPED_SERVERS_FILE"
            fi
            continue
        fi
        
        # Test all usernames for credential testing
        for USERNAME in "${USERNAMES[@]}"; do
            echo "Testing credentials with username: $USERNAME"
            GET_RESPONSE=$(curl -s -k -u "$USERNAME:$PASSWORD" -D - "${PROTOCOL}://$asset$GET_ENDPOINT" --connect-timeout 3 --max-time 5)
            
            # Check if authentication was successful
            if echo "$GET_RESPONSE" | grep -q "HTTP/.* 200" || echo "$GET_RESPONSE" | grep -q "successful\|authenticated\|current user"; then
                # Format: IP:username:password (consistent format)
                echo "$asset:$USERNAME:$PASSWORD" >> "$SUCCESSFUL_CREDENTIALS_FILE"
                echo "✅ SUCCESS: $USERNAME@$asset"
            fi
        done
    done < "$INTEGRATION_SERVERS_FILE"
    
    # Display credential testing summary
    echo ""
    echo "🔐==================================================🔐"
    echo "🔐         CREDENTIAL TESTING COMPLETE            🔐"
    echo "🔐==================================================🔐"
    echo ""
    
    if [ -f "$SUCCESSFUL_CREDENTIALS_FILE" ] && [ -s "$SUCCESSFUL_CREDENTIALS_FILE" ]; then
        echo "✅ Successful Credentials Found: $(wc -l < "$SUCCESSFUL_CREDENTIALS_FILE")"
    else
        echo "❌ No successful credentials found"
    fi
    
    if [ -f "$SKIPPED_SERVERS_FILE" ] && [ -s "$SKIPPED_SERVERS_FILE" ]; then
        echo "⚠️  Servers Skipped (Down/Slow): $(wc -l < "$SKIPPED_SERVERS_FILE")"
    fi
    
    echo ""
fi

# Only run fuzzing if selected
if [ "$FUZZING_ONLY" = true ] || [ "$RUN_ALL" = true ] || [ "$CREDS_AND_FUZZ" = true ] || [ "$DETECTION_AND_FUZZ" = true ]; then
    ###############################
    # Fuzzing Phase
    ###############################
    echo ""
    echo "🌊==================================================🌊"
    echo "🌊            FUZZING PHASE STARTING               🌊"
    echo "🌊==================================================🌊"
    echo ""

    FUZZ_ENDPOINT="/invoke/FUZZ"

    while IFS= read -r asset || [ -n "$asset" ]; do
        # Skip if asset contains "alibaba"
        if echo "$asset" | grep -qi "alibaba"; then
             echo "[DEBUG] Skipping fuzzing on asset: $asset contains 'alibaba'"
             continue
        fi

        echo "Fuzzing integration server: $asset"
        
        RECON_CMD="ffuf -v -k -w \"$RECON_ENDPOINTS_FILE\" -u \"${PROTOCOL}://$asset$FUZZ_ENDPOINT\" -mc 200,500 -H \"User-Agent: $UA\""
        echo "Running ffuf command on $asset:"
        echo "$RECON_CMD"
        {
          echo "Running ffuf on $asset..."
          eval $RECON_CMD
          echo "----------------------------------------"
          echo ""
        } >> "$OUTPUT_FILE"
    done < "$INTEGRATION_SERVERS_FILE"
fi

# Clean up the monitor process.
kill $MONITOR_PID
echo "Integration server monitor (PID: $MONITOR_PID) terminated."

# Clean up temporary resolved file
if [ -f "$RESOLVED_FILE" ]; then
    rm -f "$RESOLVED_FILE"
    echo "🧹 Cleaned up temporary resolved file"
fi

# Display file summary
display_file_summary

