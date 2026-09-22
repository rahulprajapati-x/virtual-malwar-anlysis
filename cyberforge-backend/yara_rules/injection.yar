/*
   CyberForge YARA Rules — Process & Code Injection Detection
   Covers: classic injection, process hollowing, DLL injection, APC injection
*/

rule SUSP_ProcessInjection_Classic_API
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects classic process injection API sequence"
        family      = "Injector"
        severity    = "HIGH"
        mitre       = "T1055"

    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "OpenProcess" ascii
        $api5 = "VirtualProtectEx" ascii

    condition:
        3 of ($api*)
}

rule SUSP_ProcessHollowing_API
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects process hollowing technique (T1055.012)"
        family      = "Hollowing"
        severity    = "CRITICAL"
        mitre       = "T1055.012"

    strings:
        $h1 = "CreateProcess" ascii
        $h2 = "ZwUnmapViewOfSection" ascii
        $h3 = "NtUnmapViewOfSection" ascii
        $h4 = "VirtualAllocEx" ascii
        $h5 = "WriteProcessMemory" ascii
        $h6 = "SetThreadContext" ascii
        $h7 = "ResumeThread" ascii
        $h8 = "GetThreadContext" ascii

    condition:
        $h1 and ($h2 or $h3) and $h4 and $h5 and ($h6 or $h7 or $h8)
}

rule SUSP_APC_Injection
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects APC (Asynchronous Procedure Call) injection"
        family      = "APCInjector"
        severity    = "HIGH"
        mitre       = "T1055.004"

    strings:
        $apc1 = "QueueUserAPC" ascii
        $apc2 = "NtQueueApcThread" ascii
        $apc3 = "ZwQueueApcThread" ascii
        $open = "OpenThread" ascii
        $alloc = "VirtualAllocEx" ascii

    condition:
        (any of ($apc*)) and $open and $alloc
}

rule SUSP_NtAPI_Direct_Syscall
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects direct NT API calls used to evade userland hooks"
        family      = "Evasion"
        severity    = "HIGH"
        mitre       = "T1055, T1562.001"

    strings:
        $nt1 = "NtAllocateVirtualMemory" ascii
        $nt2 = "NtWriteVirtualMemory" ascii
        $nt3 = "NtCreateThreadEx" ascii
        $nt4 = "NtProtectVirtualMemory" ascii
        $nt5 = "NtOpenProcess" ascii
        $nt6 = "ZwQueryInformationProcess" ascii
        $nt7 = "NtCreateProcess" ascii

    condition:
        3 of ($nt*)
}

rule SUSP_DLL_Injection_LoadLibrary
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects DLL injection via LoadLibrary + CreateRemoteThread"
        family      = "DLLInjection"
        severity    = "HIGH"
        mitre       = "T1055.001"

    strings:
        $dll1 = "LoadLibraryA" ascii
        $dll2 = "LoadLibraryW" ascii
        $dll3 = "LoadLibraryExA" ascii
        $rmt  = "CreateRemoteThread" ascii
        $gpa  = "GetProcAddress" ascii
        $wpm  = "WriteProcessMemory" ascii

    condition:
        any of ($dll*) and $rmt and $gpa and $wpm
}

rule SUSP_Reflective_DLL_Injection
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects reflective DLL injection (ReflectiveDLLInjection)"
        family      = "ReflectiveDLL"
        severity    = "CRITICAL"
        mitre       = "T1055.001"

    strings:
        $ref1   = "ReflectiveLoader" ascii
        $ref2   = "REFLECTIVEDLLINJECTION_EXPORTS" ascii
        $cs_ref = "ReflectiveDLLInjection" ascii

    condition:
        any of them
}
