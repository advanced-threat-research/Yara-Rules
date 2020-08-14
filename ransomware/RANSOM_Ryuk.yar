rule Ryuk_Ransomware {

   meta:

      description = "Ryuk Ransomware hunting rule"
      author = "Christiaan Beek - McAfee ATR team"
      date = "2019-04-25"
      rule_version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:W32/Ryuk"
      actor_type = "Cybercrime"
      actor_group = "Unknown"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/ryuk-ransomware-attack-rush-to-attribution-misses-the-point/"
      
   
   strings:

      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "\\System32\\cmd.exe" fullword wide
      $s1 = "C:\\Users\\Admin\\Documents\\Visual Studio 2015\\Projects\\ConsoleApplication54new crypted" ascii
      $s2 = "fg4tgf4f3.dll" fullword wide
      $s3 = "lsaas.exe" fullword wide
      $s4 = "\\Documents and Settings\\Default User\\sys" fullword wide
      $s5 = "\\Documents and Settings\\Default User\\finish" fullword wide
      $s6 = "\\users\\Public\\sys" fullword wide
      $s7 = "\\users\\Public\\finish" fullword wide
      $s8 = "You will receive btc address for payment in the reply letter" fullword ascii
      $s9 = "hrmlog" fullword wide
      $s10 = "No system is safe" fullword ascii
      $s11 = "keystorage2" fullword wide
      $s12 = "klnagent" fullword wide
      $s13 = "sqbcoreservice" fullword wide
      $s14 = "tbirdconfig" fullword wide
      $s15 = "taskkill" fullword wide

      $op0 = { 8b 40 10 89 44 24 34 c7 84 24 c4 }
      $op1 = { c7 44 24 34 00 40 00 00 c7 44 24 38 01 }
    
   condition:

      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ) and
      all of ($op*)) or
      ( all of them )
}

