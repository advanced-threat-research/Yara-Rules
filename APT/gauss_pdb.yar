rule Gauss_PDB
{
	 meta:
		 description = "Rule to detect Gauss based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "EF6451FDE3751F698B49C8D4975A58B5"

	 strings:

		 $pdb = "\\projects\\gauss\\bin\\release\\winshell.pdb"

	 condition:

	 	any of them
}
