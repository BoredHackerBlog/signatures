rule majikpos_csrss
{
    strings:
        $dotnet = "_CorExeMain"
        $csrss = "Client Server Runtime Process"
        $var1 = "ProcName"
        $var2 = "Regex"
        $var3 = "LocalIp"
        $var4 = "Hwid"
        $var5 = "PcName"
        $var6 = "Action"
    condition:
        filesize < 100KB and filesize > 40KB and uint16(0) == 0x5A4D and (all of them)
}


rule majikpos
{
    strings:
        $dotnet = "_CorExeMain"
        $var1 = "ProcName"
        $var2 = "Regex"
        $var3 = "LocalIp"
        $var4 = "Hwid"
        $var5 = "PcName"
        $var6 = "Action"
    condition:
        uint16(0) == 0x5A4D and (all of them)
}
