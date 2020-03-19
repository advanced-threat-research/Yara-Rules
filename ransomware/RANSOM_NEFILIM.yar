rule nefilim_ransomware {

   meta:

      description = "Rule to detect Nefilim ransomware"
      author = "Marc Rivero | McAfee ATR Team"

   strings:

      $s1 = "C:\\Users\\Administrator\\Desktop\\New folder\\Release\\NEFILIM.pdb" fullword ascii
      $s2 = "oh how i did it??? bypass sofos hah" fullword ascii
      $s3 = " /c timeout /t 3 /nobreak && del \"" fullword wide
      $s4 = "NEFILIM-DECRYPT.txt" fullword wide

      $op0 = { db ff ff ff 55 8b ec 83 ec 24 53 56 57 89 55 f4 }
      $op1 = { 60 be 00 d0 40 00 8d be 00 40 ff ff 57 eb 0b 90 }
      $op2 = { 84 e0 40 00 90 d1 40 00 08 }
      
   condition:

      uint16(0) == 0x5a4d and filesize < 200KB and all of ($s*) or all of ($op*) 
}
