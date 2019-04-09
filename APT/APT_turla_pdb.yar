rule APT_Turla_PDB
{
	 meta:

		 description = "Rule to detect a component of the APT Turla"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "cb1b68d9971c2353c2d6a8119c49b51f"
	 
	 strings:

	 	$pdb = "\\Workshop\\Projects\\cobra\\carbon_system\\x64\\Release\\carbon_system.pdb"

	 condition:
	 
	 	any of them
}
