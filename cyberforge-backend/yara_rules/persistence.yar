/*
   CyberForge YARA Rules — Persistence Mechanism Detection
   Covers: Registry Run keys, scheduled tasks, services, WMI, DLL hijacking
*/

rule SUSP_Registry_Persistence
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects registry-based persistence mechanisms"
        family      = "Persistence"
        severity    = "MEDIUM"
        mitre       = "T1547.001"

    strings:
        $run1 = "CurrentVersion\\Run" ascii wide nocase
        $run2 = "CurrentVersion\\RunOnce" ascii wide nocase
        $run3 = "CurrentVersion\\RunServices" ascii wide nocase
        $run4 = "CurrentVersion\\RunServicesOnce" ascii wide nocase
        $run5 = "CurrentVersion\\Policies\\Explorer\\Run" ascii wide nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii

    condition:
        any of ($run*) and any of ($api*)
}

rule SUSP_Scheduled_Task_Persistence
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects scheduled task creation for persistence"
        family      = "Persistence"
        severity    = "MEDIUM"
        mitre       = "T1053.005"

    strings:
        $task1 = "schtasks" ascii wide nocase
        $task2 = "ITaskScheduler" ascii wide
        $task3 = "ITaskService" ascii wide
        $task4 = "/Create" ascii wide nocase
        $task5 = "Schedule.Service" ascii wide
        $task6 = "SchTasks.exe" ascii wide nocase

    condition:
        2 of ($task*)
}

rule SUSP_Service_Installation
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects Windows service installation for persistence"
        family      = "Persistence"
        severity    = "MEDIUM"
        mitre       = "T1543.003"

    strings:
        $svc1 = "CreateService" ascii
        $svc2 = "OpenSCManager" ascii
        $svc3 = "StartService" ascii
        $svc4 = "ChangeServiceConfig" ascii
        $svc5 = "SERVICE_AUTO_START" ascii
        $svc6 = "sc create" ascii wide nocase

    condition:
        3 of ($svc*)
}

rule SUSP_WMI_Persistence
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects WMI event subscription for persistence (fileless)"
        family      = "Persistence"
        severity    = "HIGH"
        mitre       = "T1546.003"

    strings:
        $wmi1 = "Win32_EventFilter" ascii wide
        $wmi2 = "Win32_EventConsumer" ascii wide
        $wmi3 = "Win32_FilterToConsumerBinding" ascii wide
        $wmi4 = "ActiveScriptEventConsumer" ascii wide
        $wmi5 = "CommandLineEventConsumer" ascii wide
        $wmi6 = "winmgmt" ascii wide nocase
        $wmi7 = "WMI subscription" ascii wide nocase

    condition:
        2 of ($wmi*)
}

rule SUSP_Startup_Folder_Drop
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects file dropping into startup folder"
        family      = "Persistence"
        severity    = "MEDIUM"
        mitre       = "T1547.001"

    strings:
        $sf1 = "Startup" ascii wide nocase
        $sf2 = "Start Menu\\Programs\\Startup" ascii wide nocase
        $sf3 = "APPDATA%" ascii wide nocase
        $sf4 = "ALLUSERSPROFILE%" ascii wide nocase
        $copy = "CopyFile" ascii
        $move = "MoveFile" ascii
        $write = "CreateFile" ascii

    condition:
        any of ($sf*) and any of ($copy, $move, $write)
}

rule SUSP_Bootkit_MBR
{
    meta:
        author      = "CyberForge Threat Intel"
        description = "Detects MBR/bootkit access patterns"
        family      = "Bootkit"
        severity    = "CRITICAL"
        mitre       = "T1542.003"

    strings:
        $mbr1 = "\\\\.\\PhysicalDrive0" ascii wide
        $mbr2 = "\\\\.\\PhysicalDrive" ascii wide
        $mbr3 = "PHYSICALDRIVE" ascii wide nocase
        $dev1 = "DeviceIoControl" ascii
        $dev2 = "IOCTL_DISK_GET_DRIVE_LAYOUT" ascii

    condition:
        any of ($mbr*) and any of ($dev*)
}
