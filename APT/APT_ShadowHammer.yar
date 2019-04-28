rule shadowHammer
{

      meta:
      description = "Rule to detect ShadowHammer using the fake domain of asus and binary (overlay and not overlay, disk and memory)"
      author = "Alex Mundo | McAfee ATR Team"
      
   strings:

       $d = { 68 6F 74 66 }
       $d1 = { 61 73 75 73 }
       $d2 = { 69 78 2E 63 }
       $binary = { 44 3A 5C 43 2B 2B 5C 41 73 75 73 53 68 65 6C 6C 43 6F 64 65 5C 52 65 6C 65 61 73 65 5C 41 73 75 73 53 68 65 6C 6C 43 6F 64 65 2E 70 64 62 }

   condition:
       all of ($d*) or $binary
}
