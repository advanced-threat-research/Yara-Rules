rule nemty_ransomware {

   meta:

      description = "Rule to detect Nemty Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://www.bleepingcomputer.com/news/security/nemty-ransomware-punishes-victims-by-posting-their-stolen-data/"
      date = "2020-02-23"
      hash = "73bf76533eb0bcc4afb5c72dcb8e7306471ae971212d05d0ff272f171b94b2d4"

   strings:

      $x1 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default}" fullword ascii
      $s2 = "https://pbs.twimg.com/media/Dn4vwaRW0AY-tUu.jpg:large :D" fullword ascii
      $s3 = "MSDOS.SYS" fullword wide
      $s4 = "/c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} " ascii
      $s5 = "recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete" fullword ascii
      $s6 = "DECRYPT.txt" fullword ascii
      $s7 = "pv3mi+NQplLqkkJpTNmji/M6mL4NGe5IHsRFJirV6HSyx8mC8goskf5lXH2d57vh52iqhhEc5maLcSrIKbukcnmUwym+In1OnvHp070=" fullword ascii
      $s8 = "\\NEMTY-DECRYPT.txt\"" fullword ascii
      $s9 = "rfyPvccxgVaLvW9OOY2J090Mq987N9lif/RoIDP89luS9Ouv9gUImpgCTVGWvJzrqiS8hQ5El02LdEvKcJ+7dn3DxiXSNG1PwLrY59KzGs/gUvXnYcmT6t34qfZmr8g8" ascii
      $s10 = "IO.SYS" fullword wide
      $s11 = "QgzjKXcD1Jh/cOLBh1OMb+rWxUbToys2ArG9laNWAWk0rNIv2dnIDpc+mSbp91E8qVN8Mv8K5jC3EBr4TB8jh5Ns/onBhPZ9rLXR7wIkaXGeTZi/4/XOtO3DFiad4+vf" ascii
      $s12 = "NEMTY-DECRYPT.txt" fullword wide
      $s13 = "pvXmjPQRoUmjj0g9QZ24wvEqyvcJVvFWXc0LL2XL5DWmz8me5wElh/48FHKcpbnq8C2kwQ==" fullword ascii
      $s14 = "a/QRAGlNLvqNuONkUWCQTNfoW45DFkZVjUPn0t3tJQnHWPhJR2HWttXqYpQQIMpn" fullword ascii
      $s15 = "KeoJrLFoTgXaTKTIr+v/ObwtC5BKtMitXq8aaDT8apz98QQvQgMbncLSJWJG+bHvaMhG" fullword ascii
      $s16 = "pu/hj6YerUnqlUM9A8i+i/UhnvsIE+9XTYs=" fullword ascii
      $s17 = "grQkLxaGvL0IBGGCRlJ8Q4qQP/midozZSBhFGEDpNElwvWXhba6kTH1LoX8VYNOCZTDzLe82kUD1TSAoZ/fz+8QN7pLqol5+f9QnCLB9QKOi0OmpIS1DLlngr9YH99vt" ascii
      $s18 = "BOOTSECT.BAK" fullword wide
      $s19 = "bbVU/9TycwPO+5MgkokSHkAbUSRTwcbYy5tmDXAU1lcF7d36BTpfvzaV5/VI6ARRt2ypsxHGlnOJQUTH6Ya//Eu0jPi/6s2MmOk67csw/msiaaxuHXDostsSCC+kolVX" ascii
      $s20 = "puh4wXjVYWJzFN6aIgnClL4W/1/5Eg6bm5uEv6Dru0pfOvhmbF1SY3zav4RQVQTYMfZxAsaBYfJ+Gx+6gDEmKggypl1VcVXWRbxAuDIXaByh9aP4B2QvhLnJxZLe+AG5" ascii

   condition:
   
      ( uint16(0) == 0x5a4d and
      filesize < 400KB and
      ( 1 of ($x*) and
      4 of them ))
}
