rule Mirage_PDB
{
		 meta:
		 description = "Rule to detect Mirage samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "5FA26F410D0133F4152EA78DF3978C22"
		 hash = "1045E26819FF782015202838E2C609F7"
		 
	 strings:

		 $pdb = "\\MF-v1.2\\Server\\Debug\\Server.pdb"
		 $pdb1 = "\\fox_1.2 20110307\\MF-v1.2\\Server\\Release\\MirageFox_Server.pdb"

	condition:

		any of them
}
