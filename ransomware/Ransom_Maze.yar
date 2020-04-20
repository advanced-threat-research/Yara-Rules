import "pe"

rule _Ransom_Maze {
   meta:
      description = "Detecting MAZE Ransomware"
      author = "Christiaan Beek @ McAfee ATR"
      date = "2020-04-19"
      hash1 = "24da3ccf131b8236d3c4a8cc29482709531232ef9c9cba38266b908439dea063"
      hash2 = "63ceb2150355c19c2e3e6735d55a19acfbbe1798eafe5e50edb9ce832b69e87a"
      hash3 = "2a6c602769ac15bd837f9ff390acc443d023ee62f76e1be8236dd2dd957eef3d"
      hash4 = "5badaf28bde6dcf77448b919e2290f95cd8d4e709ef2d699aae21f7bae68a76c"

   strings:
      $x1 = "process call create \"cmd /c start %s\"" fullword wide
      $s1 = "%spagefile.sys" fullword wide
      $s2 = "%sswapfile.sys" fullword wide
      $s3 = "%shiberfil.sys" fullword wide
      $s4 = "\\wbem\\wmic.exe" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
      $s6 = "NO MUTEX | " fullword wide
      $s7 = "--nomutex" fullword wide
      $s8 = ".Logging enabled | Maze" fullword wide
      $s9 = "DECRYPT-FILES.txt" fullword wide

      $op0 = { 85 db 0f 85 07 ff ff ff 31 c0 44 44 44 44 5e 5f }
      $op1 = { 66 90 89 df 39 ef 89 fb 0f 85 64 ff ff ff eb 5a }
      $op2 = { 56 e8 34 ca ff ff 83 c4 08 55 e8 0b ca ff ff 83 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and ( 1 of ($x*) and 4 of them ) and all of ($op*)
      ) or ( all of them )
}

