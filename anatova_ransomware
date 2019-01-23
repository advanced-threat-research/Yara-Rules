rule anatova_ransomware {

   meta:

      description = "Rule to detect the Anatova Ransomware"
      author = "Marc Rivero | McAfee ATR Team"
      reference = "https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/happy-new-year-2019-anatova-is-here/"

   strings:

        $regex = /anatova[0-9]@tutanota.com/
        
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and $regex
}
