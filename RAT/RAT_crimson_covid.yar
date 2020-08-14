rule RAT_crimsonrat_covid {
   
   meta:

      description = "Rule to detect the Crimson RAT samples used in the Covid Campaign"
      author = "Marc Rivero | McAfee ATR Team"
      date = "2020-04-16"
      rule_version = "v1"
      malware_type = "rat"
      malware_family = "Rat:W32/CrimSonRAT"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://blog.malwarebytes.com/threat-analysis/2020/03/apt36-jumps-on-the-coronavirus-bandwagon-delivers-crimson-rat/"
      hash = "0ee399769a6e6e6d444a819ff0ca564ae584760baba93eff766926b1effe0010"
      hash = "b67d764c981a298fa2bb14ca7faffc68ec30ad34380ad8a92911b2350104e748"
   
   strings:

      $s1 = "g:\\dhrwarhsav\\dhrwarhsav\\obj\\Debug\\dhrwarhsav.pdb" fullword ascii
      $s2 = "dhrwarhsavdo_process" fullword ascii
      $s3 = "dhrwarhsavlist_processes" fullword ascii
      $s4 = "dhrwarhsavget_command" fullword ascii
      $s5 = "dhrwarhsavport" fullword ascii
      $s6 = ".exe|dhrwarhsav" fullword wide
      $s7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|dhrwarhsav" fullword wide
      $s8 = "$recycle.bin|dhrwarhsav" fullword wide
      $s9 = "documents and settings|dhrwarhsav" fullword wide


      $op0 = { 32 33 34 35 74 79 74 72 65 77 33 }
      $op1 = { 31 30 37 2e 31 37 35 2e 36 34 2e 32 30 39 00 00 }
      $op2 = { 32 33 34 35 79 68 66 72 64 }

   condition:

      uint16(0) == 0x5a4d and
      filesize < 30000KB and
      all of them 
}
