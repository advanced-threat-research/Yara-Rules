rule troy_malware_campaign_pdb
{
	 meta:

		 description = "Rule to detect the Operation Troy based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "3456f42bba032cff5518a5e5256cc433"
		 hash = "ebc7741e6e0115c2cf992860a7c7eae7"
	 
	 strings:

		 $pdb = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\SetKey_WinlogOn_Shell_Modify\\BD_Installer\\Release\\BD_Installer.pdb"
		 $pdb1 = "\\Work\\Make Troy\\Concealment Troy\\Exe_Concealment_Troy(Winlogon_Shell)\\Dll\\Concealment_Troy(Dll)\\Release\\Concealment_Troy.pdb"
	 
	 condition:

	 	any of them
}
