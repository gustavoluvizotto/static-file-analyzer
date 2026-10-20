rule Triage_PE_Remote_Injection_APIs
{
    meta:
        description = "PE file naming the classic remote-injection API trio"
        expected = "hits bad/dropper.exe only"

    strings:
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        all of ($api*)
}
