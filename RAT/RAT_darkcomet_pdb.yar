rule DarkcometRAT_PDB {

	 meta:
	 
		 description = "Rule to detect an old DarkcometRAT based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://www.recordedfuture.com/darkcomet-rat-analysis/"
		 date = "2013-04-22"
		 hash = "39fe4f78e7c9b23cb74b295d387010dc4ff3c355b1c943fd0c0b7e1d9b45efd1"

	 strings:

	 	$pdb = "\\Users\\MY\\AppData\\Local\\TemporaryProjects\\Chrome\\obj\\x86\\Debug\\Chrome.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 1440KB and
	 	any of them
}
