/*
   CyberForge YARA Rules — Information Stealer & Credential Theft Detection
   Covers: browser credential theft, keyloggers, clipboard stealers, LSASS dumping
*/

rule MAL_Infostealer_Browser_Credentials
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects browser credential theft targeting Chrome/Firefox/Edge"
        family      = "Infostealer"
        severity    = "HIGH"
        mitre       = "T1555.003"

    strings:
        $chrome1 = "Login Data" ascii wide
        $chrome2 = "Chrome\\User Data" ascii wide nocase
        $chrome3 = "Chromium\\User Data" ascii wide nocase
        $chrome4 = "encrypted_key" ascii wide
        $firefox1 = "logins.json" ascii wide
        $firefox2 = "key4.db" ascii wide
        $firefox3 = "cert9.db" ascii wide
        $edge1 = "Microsoft\\Edge\\User Data" ascii wide nocase
        $crypt = "CryptUnprotectData" ascii

    condition:
        (any of ($chrome*) or any of ($firefox*) or any of ($edge*)) and $crypt
}

rule MAL_LSASS_Memory_Dump
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects LSASS process memory dumping for credential extraction"
        family      = "CredentialDump"
        severity    = "CRITICAL"
        mitre       = "T1003.001"

    strings:
        $lsass1 = "lsass.exe" ascii wide nocase
        $lsass2 = "lsass" ascii wide nocase
        $dump1  = "MiniDumpWriteDump" ascii
        $dump2  = "dbghelp.dll" ascii wide nocase
        $dump3  = "dbgcore.dll" ascii wide nocase
        $priv1  = "SeDebugPrivilege" ascii wide
        $open1  = "OpenProcess" ascii
        $read1  = "ReadProcessMemory" ascii

    condition:
        ($lsass1 or $lsass2) and
        (any of ($dump*) or ($priv1 and $open1 and $read1))
}

rule MAL_Keylogger_SetWindowsHook
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects keylogger using Windows hook mechanism"
        family      = "Keylogger"
        severity    = "HIGH"
        mitre       = "T1056.001"

    strings:
        $hook1 = "SetWindowsHookEx" ascii
        $hook2 = "SetWindowsHookExA" ascii
        $hook3 = "SetWindowsHookExW" ascii
        $type1 = "WH_KEYBOARD" ascii
        $type2 = "WH_KEYBOARD_LL" ascii
        $type3 = "13" ascii         // WH_KEYBOARD_LL value
        $log1  = "GetKeyState" ascii
        $log2  = "GetAsyncKeyState" ascii
        $log3  = "MapVirtualKey" ascii

    condition:
        any of ($hook*) and (any of ($type*) or any of ($log*))
}

rule MAL_Clipboard_Stealer
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects clipboard monitoring for credential / crypto wallet theft"
        family      = "ClipboardStealer"
        severity    = "MEDIUM"
        mitre       = "T1115"

    strings:
        $clip1 = "OpenClipboard" ascii
        $clip2 = "GetClipboardData" ascii
        $clip3 = "EmptyClipboard" ascii
        $clip4 = "SetClipboardData" ascii  // Clipboard hijacking (swap wallet address)
        $format1 = "CF_TEXT" ascii
        $format2 = "CF_UNICODETEXT" ascii
        $timer1  = "SetTimer" ascii
        $timer2  = "GetTickCount" ascii

    condition:
        ($clip1 and $clip2) and
        (any of ($format*) or $timer1 or $timer2 or $clip3 or $clip4)
}

rule MAL_Stealer_Telegram_Data
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects theft of Telegram Desktop session data"
        family      = "Infostealer:Telegram"
        severity    = "HIGH"
        mitre       = "T1539, T1005"

    strings:
        $tg1 = "Telegram Desktop" ascii wide nocase
        $tg2 = "tdata" ascii wide nocase
        $tg3 = "\\Telegram\\tdata" ascii wide nocase
        $tg4 = "D877F783D5D3EF8C" ascii   // Telegram session map file key

    condition:
        2 of them
}

rule MAL_Crypto_Wallet_Stealer
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects cryptocurrency wallet file theft"
        family      = "CryptoStealer"
        severity    = "HIGH"
        mitre       = "T1005, T1552.001"

    strings:
        $w1 = "wallet.dat" ascii wide nocase
        $w2 = "Bitcoin\\wallet" ascii wide nocase
        $w3 = "Ethereum\\keystore" ascii wide nocase
        $w4 = "MetaMask" ascii wide nocase
        $w5 = "seed phrase" ascii wide nocase
        $w6 = "recovery phrase" ascii wide nocase
        $w7 = "private key" ascii wide nocase

    condition:
        2 of them
}
