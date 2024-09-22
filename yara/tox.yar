rule possible_tox_usage
{
    strings:
        $a = "libsodium"
        $b = "libtox"
        $c = "tox_bootstrap"
    condition:
        (all of them) and uint16(0) == 0x5A4D
}

rule possible_tox_vivian
{
    strings:
        $a = "vivian"
        $b = "!exec"
        $c = "!version"
        $d = "!sysinfo"
        $e = "!wget"
    condition:
        (all of them) and uint16(0) == 0x5A4D
}

rule possible_tox_bot
{
    strings:
        $a = "hacking corps for money"
        $b = "libtox"
        $c = "fffline"
        $d = "Evil"
    condition:
        (all of them) and uint16(0) == 0x5A4D
}
