rule RAT_comrat {
	 
	 meta:
	 
		 description = "Rule to detect the ComRAT RAT based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-08-20"
		 rule_version = "v1"
         malware_type = "rat"
         malware_family = "Rat:W32/ComRAT"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified"
		 hash = "63658c331ac38322935d6dcde8bd892aa99084a0cea91bbef3b7789b02bf8d0e"
		
	 strings:

	     $pdb = "\\projects\\ChinckSkx64\\Debug\\Chinch.pdb"

	 condition:
	 
	 	uint16(0) == 0x5a4d and
	 	filesize < 440KB and
	 	any of them
}
