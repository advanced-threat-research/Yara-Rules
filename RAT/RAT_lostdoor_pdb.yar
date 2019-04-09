rule LostdoorRAT_pdb
{
	 meta:
		 description = "Rule to detect LostdoorRAT based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "FB1B0536B4660E67E8AA7BAB17994A7C"
		 
	 strings:

	 	$pdb = "\\Users\\Aegis\\Documents\\Visual Studio 2008\\Projects\\stub1\\Release\\stub.pdb"

	 condition:
	 
	 	any of them
}
