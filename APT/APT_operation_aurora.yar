rule apt_aurora_pdb_samples {
	 
	meta:
	 
		 description = "Aurora APT Malware 2006-2010"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://en.wikipedia.org/wiki/Operation_Aurora"
		 date = "2010-01-11"
		 hash = "f0c78171b11b40f40e24dd9eaa8a3a381e1816ab8c3653aeb167e94803f90430"
		 hash = "ce7debbcf1ca3a390083fe5753f231e632017ca041dfa662ad56095a500f2364"
		 
 	strings:

		 $pdb = "\\AuroraVNC\\VedioDriver\\Release\\VedioDriver.pdb"
		 $pdb1 = "\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"
	 
 	condition:
 
 		uint16(0) == 0x5a4d and
 		filesize < 150KB and
 		any of them
}
