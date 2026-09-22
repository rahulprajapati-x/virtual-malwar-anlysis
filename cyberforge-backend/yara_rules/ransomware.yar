/*
   CyberForge YARA Rules — Ransomware Families
   Covers: generic ransomware behavior, Ryuk, LockBit, WannaCry, REvil/Sodinokibi
*/

rule MAL_Ransomware_ShadowCopy_Deletion
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects shadow copy deletion — key ransomware pre-encryption step"
        family      = "Ransomware"
        severity    = "CRITICAL"
        mitre       = "T1490"

    strings:
        $vss1  = "vssadmin" ascii nocase
        $vss2  = "delete shadows" ascii nocase
        $vss3  = "wbadmin delete catalog" ascii nocase
        $vss4  = "wmic shadowcopy delete" ascii nocase
        $vss5  = "DisableLastAccess" ascii nocase
        $bcd1  = "bcdedit /set" ascii nocase
        $bcd2  = "recoveryenabled No" ascii nocase
        $bcd3  = "bootstatuspolicy ignoreallfailures" ascii nocase

    condition:
        any of ($vss*) or (all of ($bcd*))
}

rule MAL_Ransomware_FileEncryption_API
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects Windows crypto API usage pattern consistent with ransomware"
        family      = "Ransomware"
        severity    = "HIGH"
        mitre       = "T1486"

    strings:
        $crypt1 = "CryptAcquireContext" ascii
        $crypt2 = "CryptEncrypt" ascii
        $crypt3 = "CryptGenKey" ascii
        $crypt4 = "CryptImportKey" ascii
        $rsa1   = "BCryptEncrypt" ascii
        $rsa2   = "BCryptGenerateKeyPair" ascii
        $rsa3   = "BCryptOpenAlgorithmProvider" ascii
        $enum1  = "FindFirstFileW" ascii
        $enum2  = "FindNextFileW" ascii

    condition:
        (2 of ($crypt*) or 2 of ($rsa*)) and (any of ($enum*))
}

rule MAL_Ransomware_Ryuk
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects Ryuk ransomware indicators"
        family      = "Ryuk"
        severity    = "CRITICAL"
        mitre       = "T1486, T1489, T1490"
        reference   = "https://attack.mitre.org/software/S0446/"

    strings:
        $s1 = "RyukReadMe" ascii nocase wide
        $s2 = "RYUK" wide ascii
        $s3 = "lol your shit is encrypted" ascii nocase
        $s4 = "We are ready to" ascii
        $s5 = "bitcoins" ascii nocase wide
        $note1 = "RyukReadMe.txt" ascii wide
        $note2 = "RyukReadMe.html" ascii wide
        $api1 = "CreateFileW" ascii
        $api2 = "WriteFile" ascii
        $api3 = "MoveFileExW" ascii

    condition:
        2 of ($s*) or any of ($note*) or
        (all of ($api*) and 1 of ($s*))
}

rule MAL_Ransomware_LockBit
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects LockBit ransomware family indicators"
        family      = "LockBit"
        severity    = "CRITICAL"
        mitre       = "T1486, T1490, T1562"

    strings:
        $s1 = "LockBit" wide ascii nocase
        $s2 = "Restore-My-Files.txt" ascii wide
        $s3 = ".lockbit" ascii wide nocase
        $s4 = "3VM8RLa4" ascii           // Mutex pattern
        $s5 = "LOCK_" ascii nocase
        $api1 = "CreateIoCompletionPort" ascii  // Fast encryption via IOCP
        $api2 = "PostQueuedCompletionStatus" ascii
        $api3 = "GetQueuedCompletionStatus" ascii
        $ransom1 = "All your files are" ascii nocase
        $ransom2 = "encrypted by" ascii nocase

    condition:
        2 of ($s*) or
        (all of ($api*)) or
        (all of ($ransom*) and 1 of ($api*))
}

rule MAL_Ransomware_WannaCry
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects WannaCry/WannaCrypt ransomware"
        family      = "WannaCry"
        severity    = "CRITICAL"
        mitre       = "T1486, T1210, T1083"
        reference   = "https://attack.mitre.org/software/S0366/"

    strings:
        $s1  = "WannaCrypt" wide ascii
        $s2  = "WCRY" wide ascii
        $s3  = "wncry" wide ascii
        $s4  = "tasksche.exe" ascii wide
        $s5  = "mssecsvc.exe" ascii wide
        $s6  = "Please Read Me!.txt" ascii wide
        $s7  = "@Please_Read_Me@.txt" ascii wide
        $kill = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii  // kill switch domain
        $smb  = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                  53 4D 42 }  // SMB header marker

    condition:
        2 of ($s*) or $kill or
        ($smb and 1 of ($s*))
}

rule MAL_Ransomware_Generic_Note
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Generic ransom note string detection"
        family      = "Ransomware"
        severity    = "HIGH"
        mitre       = "T1486"

    strings:
        $note1 = "Your files have been encrypted" ascii nocase wide
        $note2 = "All your files are encrypted" ascii nocase wide
        $note3 = "To decrypt your files" ascii nocase wide
        $note4 = "Buy decryption tool" ascii nocase wide
        $note5 = "Pay the ransom" ascii nocase wide
        $note6 = "contact us to get your decryption key" ascii nocase wide
        $bitcoin1 = "bitcoin" ascii nocase wide
        $bitcoin2 = "BTC wallet" ascii nocase wide
        $bitcoin3 = "monero" ascii nocase wide

    condition:
        (1 of ($note*)) and (1 of ($bitcoin*))
}
