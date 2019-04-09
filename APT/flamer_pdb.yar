rule Flamer_PDB
{
	 meta:
	 description = "Rule to detect Flamer based on the PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "581F2EF2E3BA164281B562E435882EB5"
	 
	 strings:

	 	$pdb = "\\Projects\\Jimmy\\jimmydll_v2.0\\JimmyForClan\\Jimmy\\bin\\srelease\\jimmydll\\indsvc32.pdb"

	 condition:

		 any of them
}
