rule troy_malware_campaign_pdb {

	 meta:

		 description = "Rule to detect the Operation Troy based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://www.mcafee.com/enterprise/en-us/assets/white-papers/wp-dissecting-operation-troy.pdf"
		 date = "2013-06-23"
		 hash = "93fbe550387be51f978d9b62fe8befdb94331ce7db4c2206c59e20a1e9a2c968"
		 hash = "2ca6b7e9488c1e9f39392e696704ad3f2b82069e35bc8001d620024ebbf2d65a"
	 
	 strings:

		 $pdb = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\SetKey_WinlogOn_Shell_Modify\\BD_Installer\\Release\\BD_Installer.pdb"
		 $pdb1 = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\Dll\\Concealment_Troy(Dll)\\Release\\Concealment_Troy.pdb"
	 
	 condition:

	 	uint16(0) == 0x5a4d and
 		filesize < 500KB and
 		any of them
}
