rule manitsme_trojan
{
	 meta:
		 description = "Rule to detect Manitsme based on PDB"
		 author = "Marc Rivero Lopez"
		 hash = "E97EBB5B2050B86999C55797C2348BA7"
	 
	 strings:

	 	$pdb = "\\rouji\\SvcMain.pdb"

	 condition:
	 
	 	any of them
}
