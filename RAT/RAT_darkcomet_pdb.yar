rule RAT_darkcomet_pdb {

	 meta:
	 
		 description = "Rule to detect an old DarkcometRAT based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-04-22"
		 rule_version = "v1"
         malware_type = "rat"
         malware_family = "Rat:W32/DarkComet"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://www.recordedfuture.com/darkcomet-rat-analysis/"		 
		 hash = "39fe4f78e7c9b23cb74b295d387010dc4ff3c355b1c943fd0c0b7e1d9b45efd1"

	 strings:

	 	$pdb = "\\Users\\MY\\AppData\\Local\\TemporaryProjects\\Chrome\\obj\\x86\\Debug\\Chrome.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 1440KB and
	 	any of them
}
