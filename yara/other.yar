rule windivert_use_dotnet { 
strings: 
  $a = "windivert.dll" nocase
  $b = "WinDivertOpen"
  $c = "WinDivertRecv"
  $d = "WinDivertSharp"
  $dotnet = "_CorExeMain"
condition: uint16(0) == 0x5a4d and (all of them) 
}

rule windivert_cs {
strings:
  $a1 = "WinDivertSharp"
  $a2 = "WinDivertOpen"
  $a3 = "WinDivertLayer"
  $a4 = "WinDivertSend"
  $a5 = "WinDivertClose"
  $b1 = "Divert.Net"
  $b2 = "Diversion"
  $b3 = "DivertLayer"
condition: 
    uint16(0) == 0x5a4d and 
    (
    ($a1 and $a2 and $a3 and $a4 and $a5) or ($b1 and $b2 and $b3)
    ) 
}

rule windivert_py {
strings:
  $a = "packet"
  $b = "pydivert"
  $c = "python" nocase
condition:  uint16(0) == 0x5a4d and (all of them)
}
