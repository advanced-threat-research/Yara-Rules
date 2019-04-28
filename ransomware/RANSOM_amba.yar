rule amba_ransomware {
   
   meta:

      description = "Rule to detect Amba Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      hash1 = "7c08cdf9f4e8be34ef6af5b53794163023c2b013f34c4134b8922f42933012a0"
      hash2 = "73155a084aac8434bb0779a0b88e97d5cf2d0760e9d25f2f42346d3e06cdaac2"
      hash3 = "ec237bc926ce9008a219b8b30882f3ac18531bd314ee852369fc712368c6acd5"
      hash4 = "b9b6045a45dd22fcaf2fc13d39eba46180d489cb4eb152c87568c2404aecac2f"

   strings:

      $s1 = "64DCRYPT.SYS" fullword wide
      $s2 = "32DCRYPT.SYS" fullword wide
      $s3 = "64DCINST.EXE" fullword wide
      $s4 = "32DCINST.EXE" fullword wide
      $s5 = "32DCCON.EXE" fullword wide
      $s6 = "64DCCON.EXE" fullword wide
      $s8 = "32DCAPI.DLL" fullword wide
      $s9 = "64DCAPI.DLL" fullword wide
      $s10 = "ICYgc2h1dGRvd24gL2YgL3IgL3QgMA==" fullword ascii 
      $s11 = "QzpcVXNlcnNcQUJDRFxuZXRwYXNzLnR4dA==" fullword ascii 
      $s12 = ")!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v))!pssx}v!pssx}v)" fullword ascii
      $s13 = "RGVmcmFnbWVudFNlcnZpY2U=" 
      $s14 = "LWVuY3J5cHQgcHQ5IC1wIA==" 
      $s15 = "LWVuY3J5cHQgcHQ3IC1wIA==" 
      $s16 = "LWVuY3J5cHQgcHQ2IC1wIA==" 
      $s17 = "LWVuY3J5cHQgcHQzIC1wIA==" 

   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}
