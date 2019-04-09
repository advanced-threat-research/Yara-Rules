rule apt_blackenergy_pdb
{
	 meta:
		 description = "APT Blackenergy PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "FD111A5496B6336B8503AE02FFA04E28"
		
	 strings:

	 	$pdb = "\\CB\\11X_Security\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb"
	 
	 condition:

	 	any of them
}
