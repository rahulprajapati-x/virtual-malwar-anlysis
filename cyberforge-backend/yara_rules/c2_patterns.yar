/*
   CyberForge YARA Rules — C2 Communication Pattern Detection
   Covers: HTTP C2, DNS tunneling, custom protocols, beaconing patterns
*/

rule SUSP_HTTP_C2_Pattern
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects HTTP-based C2 communication patterns"
        family      = "C2"
        severity    = "HIGH"
        mitre       = "T1071.001"

    strings:
        $ua1 = "User-Agent:" ascii nocase
        $ua2 = "Mozilla/5.0" ascii
        $gate1 = "/gate.php" ascii
        $gate2 = "/connect.php" ascii
        $gate3 = "/update.php" ascii
        $gate4 = "/check.php" ascii
        $gate5 = "/beacon.php" ascii
        $http1 = "POST" ascii
        $http2 = "Content-Type: application/x-www-form-urlencoded" ascii

    condition:
        any of ($gate*) and ($http1 or $http2 or $ua1 or $ua2)
}

rule SUSP_DNS_Tunneling
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects DNS tunneling indicators for covert C2"
        family      = "C2:DNS"
        severity    = "HIGH"
        mitre       = "T1071.004"

    strings:
        $dns1 = "DnsQuery" ascii
        $dns2 = "DnsQueryA" ascii
        $dns3 = "DnsQueryW" ascii
        $dns4 = "DnsQuery_A" ascii
        $b641 = "base64" ascii nocase
        $b642 = { 41 41 41 41 41 41 41 41 41 41 }  // Long base64-like sequence
        $txt1 = "TXT" ascii
        $txt2 = "DNS_TYPE_TEXT" ascii

    condition:
        any of ($dns*) and (any of ($b64*) or any of ($txt*))
}

rule SUSP_CobaltStrike_Beacon
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects Cobalt Strike beacon indicators"
        family      = "CobaltStrike"
        severity    = "CRITICAL"
        mitre       = "T1071.001, T1055, T1573"
        reference   = "https://attack.mitre.org/software/S0154/"

    strings:
        $cs1  = "%s (admin)" ascii
        $cs2  = "beacon.dll" ascii nocase
        $cs3  = "MSSE-" ascii
        $cs4  = "ReflectiveDLL" ascii
        $cs5  = "beacon_gate" ascii
        $cs6  = "COBALTSTRIKE" ascii nocase
        $mem1 = { FC E8 [4-6] 60 89 E5 31 C0 }    // Common shellcode prologue
        $mem2 = { FC 48 83 E4 F0 E8 }               // x64 shellcode prologue
        $pipe1 = "\\\\.\\pipe\\MSSE-" ascii
        $pipe2 = "\\\\.\\pipe\\msagent_" ascii

    condition:
        2 of ($cs*) or any of ($mem*) or any of ($pipe*)
}

rule SUSP_Metasploit_Meterpreter
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects Metasploit Meterpreter indicators"
        family      = "Meterpreter"
        severity    = "CRITICAL"
        mitre       = "T1071.001"
        reference   = "https://attack.mitre.org/software/S0368/"

    strings:
        $m1 = "meterpreter" ascii nocase wide
        $m2 = "Meterpreter" ascii
        $m3 = "LPORT" ascii
        $m4 = "LHOST" ascii
        $m5 = "reverse_tcp" ascii nocase
        $m6 = "windows/shell" ascii nocase
        $m7 = "payload/windows" ascii nocase

    condition:
        2 of them
}

rule SUSP_NetworkScan_Pattern
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects internal network scanning / lateral movement indicators"
        family      = "Reconnaissance"
        severity    = "MEDIUM"
        mitre       = "T1046, T1018"

    strings:
        $scan1 = "net view" ascii nocase wide
        $scan2 = "net use" ascii nocase wide
        $scan3 = "NetShareEnum" ascii
        $scan4 = "GetAdaptersInfo" ascii
        $scan5 = "GetIpAddrTable" ascii
        $scan6 = "arp -a" ascii wide nocase
        $scan7 = "nbtscan" ascii nocase
        $scan8 = "nmap" ascii nocase wide

    condition:
        3 of ($scan*)
}

rule SUSP_TOR_Communication
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects hardcoded TOR/onion addresses or TOR usage"
        family      = "C2:TOR"
        severity    = "HIGH"
        mitre       = "T1090.003"

    strings:
        $tor1 = ".onion" ascii wide nocase
        $tor2 = "127.0.0.1:9050" ascii     // Default TOR SOCKS
        $tor3 = "127.0.0.1:9150" ascii     // TOR Browser SOCKS
        $tor4 = "torproject.org" ascii nocase
        $socks = "SOCKS5" ascii nocase

    condition:
        any of ($tor*) or $socks
}
