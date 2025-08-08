
 INTEGRATION SURFER v1.0 - WebMethods Integration Server Reconnaissance Tool


 Usage: ./Integration_Surfer.sh <ips_file> <output_file> [options]

 REQUIRED ARGUMENTS:
   <ips_file>      : File containing one asset per line (IPs or domains, e.g., integration_ips.txt)
   <output_file>   : File to which recon output is appended

 OPTIONAL ARGUMENTS:
   -p, --port PORT     Port to use (default: 443)

 INTERACTIVE MENU OPTIONS:
   After providing required arguments, the script presents an interactive menu:
   1. 🏄‍♂️ Integration Server Detection (tests 9 endpoints)
      - Scans for WebMethods Integration Server instances
      - Tests 9 different endpoints to identify servers
   2. 🔐 Default Credential Testing (tests 6 credentials)
      - Tests common default credentials on discovered servers
      - Tests: Administrator/manage, Sysadmin/manage, designer/manage, etc.
   3. 🌊 Fuzzing (runs ffuf over everything)
      - Performs comprehensive fuzzing using ffuf
      - Uses extensive wordlist from IntegrationServerFUZZ.txt
   4. 🏄‍♀️ Run All Tests (detection + credentials + fuzzing)
      - Complete reconnaissance pipeline
      - Original behavior - runs all phases sequentially
   5. 🏄‍♂️ Test Credentials and Fuzz (skip detection, assume good data)
      - Skips server detection phase
      - Assumes you already have confirmed servers
      - Runs credential testing + fuzzing only
   6. 🔐 Detection + Credentials only (no fuzzing)
      - Server detection + credential testing
      - Skips resource-intensive fuzzing phase
   7. 🌊 Detection + Fuzzing only (no credentials)
      - Server detection + fuzzing
      - Skips credential testing phase

 REQUIRED FILES:
   - integration_ips.txt: List of IP addresses or domains to scan
   - IntegrationServerFUZZ.txt: Extended fuzzing data 

 OUTPUT FILES:
   - confirmedIntegrationservers.txt: Discovered integration servers
   - successful_credentials.txt: Found valid credentials
   - <output_file>: Detailed scan results and logs

 EXAMPLE USAGE:
  ./Integration_Surfer.sh integration_ips.txt results.txt

