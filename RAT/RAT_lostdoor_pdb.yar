rule RAT_lostdoor_pdb {
	 
	 meta:

		 description = "Rule to detect LostdoorRAT based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 date = "2013-11-25"
         rule_version = "v1"
         malware_type = "rat"
         malware_family = "Rat:W32/LostDoor"
         actor_type = "Cybercrime"
         actor_group = "Unknown"
		 reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/lost-door-rat-accessible-customizable-attack-tool/"
		 hash = "28d0d2611d0fa6309991c1fbd24fe2596891b09f4f6568e6c9328abc9390f5a6"
		 
	 strings:

	 	 $pdb = "\\Users\\Aegis\\Documents\\Visual Studio 2008\\Projects\\stub1\\Release\\stub.pdb"

	 condition:
	 
	 	uint16(0) == 0x5a4d and
	 	filesize < 400KB and
	 	any of them
}
