import "pe"
import "math"

/*
   CyberForge YARA Rules — Packer & Obfuscation Detection
   Covers: UPX, MPRESS, ASPack, custom packers, high entropy, encoding
*/

rule SUSP_UPX_Packed
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects UPX packed binary"
        family      = "Packer:UPX"
        severity    = "LOW"
        mitre       = "T1027.002"

    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX2" ascii
        $upx4 = "UPX!" ascii
        $upx5 = { 55 50 58 21 }  // UPX! bytes

    condition:
        any of them
}

rule SUSP_MPRESS_Packed
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects MPRESS packed binary"
        family      = "Packer:MPRESS"
        severity    = "LOW"
        mitre       = "T1027.002"

    strings:
        $m1 = ".MPRESS1" ascii
        $m2 = ".MPRESS2" ascii

    condition:
        any of them
}

rule SUSP_HighEntropy_ExecutableSection
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects executable section with very high entropy indicating encryption/packing"
        family      = "Packer:Generic"
        severity    = "MEDIUM"
        mitre       = "T1027"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0 and
        for any section in pe.sections : (
            section.characteristics & pe.SECTION_MEM_EXECUTE and
            section.characteristics & pe.SECTION_MEM_WRITE and
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.2
        )
}

rule SUSP_Powershell_Encoded_Command
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects PowerShell with encoded/obfuscated command execution"
        family      = "Obfuscation"
        severity    = "MEDIUM"
        mitre       = "T1059.001, T1027"

    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-EncodedCommand" ascii wide nocase
        $enc3 = "-e " ascii wide nocase
        $iex1 = "IEX" ascii wide
        $iex2 = "Invoke-Expression" ascii wide nocase
        $iex3 = "iex(" ascii wide nocase

    condition:
        (any of ($ps*)) and (any of ($enc*) or any of ($iex*))
}

rule SUSP_Powershell_Download_Cradle
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects PowerShell download cradle (fileless delivery)"
        family      = "Downloader"
        severity    = "HIGH"
        mitre       = "T1059.001, T1105"

    strings:
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "WebClient" ascii wide nocase
        $dl4 = "Net.WebClient" ascii wide nocase
        $dl5 = "Invoke-WebRequest" ascii wide nocase
        $dl6 = "wget" ascii wide nocase
        $dl7 = "curl" ascii wide nocase
        $iex = "IEX" ascii wide

    condition:
        any of ($dl*) and $iex
}

rule SUSP_XOR_Encoded_Shellcode
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects common XOR decoding loop pattern used in shellcode loaders"
        family      = "Shellcode"
        severity    = "HIGH"
        mitre       = "T1027"

    strings:
        // MOV ECX + XOR loop pattern
        $xor1 = { B9 ?? ?? ?? ?? 8B 04 ?? 33 04 ?? 83 C? 01 }
        // REP-based XOR variants
        $xor2 = { 30 ?? ?? 4? 7? }
        // Common XOR decryption key pattern
        $key1 = "XOR_KEY" ascii
        $key2 = "decrypt_key" ascii nocase

    condition:
        any of ($xor*) or any of ($key*)
}

rule SUSP_Obfuscated_VBA_Macro
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects obfuscated VBA macro indicators in Office documents"
        family      = "MacroObfuscation"
        severity    = "HIGH"
        mitre       = "T1564.007, T1027"

    strings:
        $vba1 = "VBA" ascii
        $auto1 = "AutoOpen" ascii nocase wide
        $auto2 = "AutoClose" ascii nocase wide
        $auto3 = "Document_Open" ascii nocase wide
        $auto4 = "Workbook_Open" ascii nocase wide
        $shell1 = "Shell(" ascii nocase
        $shell2 = "WScript.Shell" ascii nocase
        $shell3 = "CreateObject" ascii nocase wide
        $enc1 = "Chr(" ascii nocase
        $enc2 = "Asc(" ascii nocase

    condition:
        $vba1 and (any of ($auto*)) and
        (any of ($shell*)) and (any of ($enc*))
}
