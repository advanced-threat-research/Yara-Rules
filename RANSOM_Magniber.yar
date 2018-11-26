rule magniber_test_unpacked_ransomware {

 meta:

      description = "Rule to detect Magniber ransomware samples" 
      author = "Marc Rivero | ATR Team" 

strings:
      $s1 = ":\\documents and settings\\default user\\" fullword wide
      $s2 = ":\\documents and settings\\networkservice\\" fullword wide
      $s3 = ":\\documents and settings\\all users\\" fullword wide
      $s4 = ":\\documents and settings\\localservice\\" fullword wide
      $s5 = "\\appdata\\roaming\\" fullword wide
      $s6 = "\\appdata\\locallow\\" fullword wide
      $s7 = "\\appdata\\local\\" fullword wide
      $s8 = "\\recycler" fullword wide
      $s9 = "\\$recycle.bin" fullword wide
      $s10 = "\\system volume information" fullword wide
      $s11 = "\\perflogs" fullword wide
      $s12 = "\\public\\pictures\\sample pictures\\" fullword wide
      $s13 = "\\public\\videos\\sample videos\\" fullword wide
      $s14 = "\\windows.old" fullword wide
      $s15 = "\\recycled" fullword wide
      $s16 = "\\public\\music\\sample music\\" fullword wide
      $s17 = "wallet" fullword wide
      $s18 = "sqlitedb" fullword wide

   condition:

      uint16(0) == 0x5a4d and filesize < 100KB or 8 of them
}
