rule FileScope_Suspicious_PowerShell_EncodedCommand
{
    meta:
        description = "Finds common PowerShell encoded-command syntax"
        severity = "medium"
    strings:
        $ps = "powershell" nocase ascii wide
        $enc1 = "-enc" nocase ascii wide
        $enc2 = "-encodedcommand" nocase ascii wide
    condition:
        $ps and 1 of ($enc*)
}

rule FileScope_Windows_Process_Injection_APIs
{
    meta:
        description = "Finds a combination of Windows APIs commonly associated with process injection"
        severity = "high"
    strings:
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread1 = "CreateRemoteThread" ascii wide
        $thread2 = "NtCreateThreadEx" ascii wide
    condition:
        $alloc and $write and 1 of ($thread*)
}

rule FileScope_Android_Dynamic_Code_Loading
{
    meta:
        description = "Finds Android dynamic code loading markers"
        severity = "medium"
    strings:
        $dex = "Ldalvik/system/DexClassLoader;" ascii
        $path = "Ldalvik/system/PathClassLoader;" ascii
        $load = "loadDex" ascii
    condition:
        2 of them
}

rule FileScope_Possible_Embedded_PE
{
    meta:
        description = "Finds an MZ header away from the beginning of another file"
        severity = "informational"
    strings:
        $mz = { 4D 5A }
    condition:
        for any i in (2..#mz) : (@mz[i] > 1024)
}

rule FileScope_Possible_Credential_Labels
{
    meta:
        description = "Finds credential-like labels; context is required"
        severity = "low"
    strings:
        $api1 = "api_key=" nocase ascii wide
        $api2 = "api-key:" nocase ascii wide
        $secret = "client_secret" nocase ascii wide
        $token = "access_token" nocase ascii wide
        $password = "password=" nocase ascii wide
    condition:
        any of them
}

rule FileScope_Common_Packer_Markers
{
    meta:
        description = "Finds common executable packer markers"
        severity = "informational"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
        $vmp = "VMProtect" ascii wide
        $themida = "Themida" ascii wide
        $aspack = ".aspack" ascii
    condition:
        2 of ($upx*) or any of ($vmp, $themida, $aspack)
}

rule FileScope_Cryptocurrency_Miner_Markers
{
    meta:
        description = "Finds several strings frequently present in cryptocurrency miners"
        severity = "medium"
    strings:
        $stratum = "stratum+tcp://" nocase ascii wide
        $xmrig = "XMRig" nocase ascii wide
        $pool1 = "mining_pool" nocase ascii wide
        $pool2 = "pool_address" nocase ascii wide
        $algo1 = "cryptonight" nocase ascii wide
        $algo2 = "randomx" nocase ascii wide
    condition:
        2 of them
}

rule FileScope_Webshell_Command_Parameters
{
    meta:
        description = "Finds common command-execution patterns in server-side web files"
        severity = "high"
    strings:
        $php1 = "system($_" nocase ascii
        $php2 = "shell_exec($_" nocase ascii
        $php3 = "passthru($_" nocase ascii
        $php4 = "eval(base64_decode(" nocase ascii
        $asp1 = "Request[\"cmd\"]" nocase ascii wide
        $asp2 = "Request['cmd']" nocase ascii wide
        $jsp = "Runtime.getRuntime().exec(" ascii wide
    condition:
        any of them
}

rule FileScope_Suspicious_Scheduled_Task_Command
{
    meta:
        description = "Finds command lines that create scheduled tasks"
        severity = "medium"
    strings:
        $tool = "schtasks" nocase ascii wide
        $create = "/create" nocase ascii wide
    condition:
        $tool and $create
}
