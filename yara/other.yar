rule windivert_use_dotnet { 
strings: 
  $a = "windivert.dll" nocase
  $b = "WinDivertOpen"
  $c = "WinDivertRecv"
  $d = "WinDivertSharp"
  $dotnet = "_CorExeMain"
condition: uint16(0) == 0x5a4d and (all of them) 
}
