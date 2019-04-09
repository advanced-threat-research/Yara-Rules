rule ixeshe_bled_malware_pdb
{
	 meta:
		 description = "Rule to detect Ixeshe_bled malware based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "E658B571FD1679DABFC2232991F712B0"
		 
	 strings:

	 	$pdb = "\\code\\Blade2009.6.30\\Blade2009.6.30\\EdgeEXE_20003OC\\Debug\\EdgeEXE.pdb"

	 condition:

	 	any of them
}
