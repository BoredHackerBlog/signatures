rule gsh_backdoor
{
    strings:
        $a = "startInteractive"
        $b = "main.winService"
        $c = "main.(*winService).Start"
    condition:
        ($a and $b and $c) and filesize < 6MB and filesize > 2MB
and uint16(0) == 0x5A4D
}

rule geo_backdoor
{
    strings:
        $a = "geodezine"
        $b = "cmd.exe"
        $c = "URLDownloadToFilDeleteUrlCacheEn"
    condition:
        ($a and $b and $c) and filesize < 100KB and uint16(0) == 0x5A4D
}

rule elf_backdoor_fipps
{
    strings:
        $a = "found mac address"
        $b = "RecvThread"
        $c = "OpenSSL-1.0.0-fipps"
        $d = "Disconnected!"
    condition:
        (all of them) and uint32(0) == 0x464c457f
}
