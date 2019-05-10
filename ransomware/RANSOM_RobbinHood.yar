
rule Robbinhood ransomware {
   meta:
      description = "Robbinhood GoLang ransowmare"
      author = "Christiaan Beek @ McAfee ATR"
      date = "2019-05-10"
      hash1 = "9977ba861016edef0c3fb38517a8a68dbf7d3c17de07266cfa515b750b0d249e"
      hash2 = "27f9f740263b73a9b7e6dd8071c8ca2b2c22f310bde9a650fc524a4115f2fa14"
      hash3 = "3bc78141ff3f742c5e942993adfbef39c2127f9682a303b5e786ed7f9a8d184b"
      hash4 = "4e58b0289017d53dda4c912f0eadf567852199d044d2e2bda5334eb97fa0b67c"
      hash5 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
      hash6 = "e128d5aa0b5a9c6851e69cbf9d2c983eefd305a10cba7e0c8240c8e2f79a544f"
   strings:
      $s1 = ".enc_robbinhood" nocase
      $s2 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s3 = "pub.key" nocase
      $s4 = "main.EnableShadowFucks" nocase
      $s5 = "main.EnableRecoveryFCK" nocase
      $s6 = "main.EnableLogLaunders" nocase
      $s7 = "main.EnableServiceFuck" nocase
     

      $op0 = { 8d 05 2d 98 51 00 89 44 24 30 c7 44 24 34 1d }
      $op1 = { 8b 5f 10 01 c3 8b 47 04 81 c3 b5 bc b0 34 8b 4f }
      $op2 = { 0f b6 34 18 8d 7e d0 97 80 f8 09 97 77 39 81 fd }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 1 of ($s*) ) and all of ($op*)
      ) or ( all of them )
}

