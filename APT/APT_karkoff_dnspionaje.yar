rule karkoff_dnspionaje {
   
   meta:

      description = "Rule to detect the Karkoff malware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      
   strings:
   
      $s1 = "DropperBackdoor.Newtonsoft.Json.dll" fullword wide
      $s2 = "C:\\Windows\\Temp\\MSEx_log.txt" fullword wide
      $s3 = "DropperBackdoor.exe" fullword wide
      $s4 = "get_ProcessExtensionDataNames" fullword ascii
      $s5 = "get_ProcessDictionaryKeys" fullword ascii
      $s6 = "https://www.newtonsoft.com/json 0" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}
