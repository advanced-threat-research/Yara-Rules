import "pe"

rule nefilim_ransomware {

   meta:

      description = "Rule to detect Nefilim ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
      date = "2020-03-17"
      hash = "5ab834f599c6ad35fcd0a168d93c52c399c6de7d1c20f33e25cb1fdb25aec9c6"

   strings:

      $s1 = "C:\\Users\\Administrator\\Desktop\\New folder\\Release\\NEFILIM.pdb" fullword ascii
      $s2 = "oh how i did it??? bypass sofos hah" fullword ascii
      $s3 = " /c timeout /t 3 /nobreak && del \"" fullword wide
      $s4 = "NEFILIM-DECRYPT.txt" fullword wide

      $op0 = { db ff ff ff 55 8b ec 83 ec 24 53 56 57 89 55 f4 }
      $op1 = { 60 be 00 d0 40 00 8d be 00 40 ff ff 57 eb 0b 90 }
      $op2 = { 84 e0 40 00 90 d1 40 00 08 }
      
   condition:

      uint16(0) == 0x5a4d and
      filesize < 200KB and
      all of ($s*) or
      all of ($op*) 
}

rule nefilim_signed {

    meta:

        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Nefilim samples digitally signed"
        reference = "https://www.bleepingcomputer.com/news/security/new-nefilim-ransomware-threatens-to-release-victims-data/"
        date = "2020-04-02"
        hash = "353ee5805bc5c7a98fb5d522b15743055484dc47144535628d102a4098532cd5"
        
    condition:

      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Red GmbH/CN=Red GmbH"  and
         pe.signatures[i].serial == "00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or
         pe.signatures[i].thumbprint == "5b:19:58:8b:78:74:0a:4c:5d:08:41:99:dc:0f:52:a6:1f:38:00:99")
}
