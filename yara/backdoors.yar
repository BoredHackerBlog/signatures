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
