rule apt_auriga_biscuit
{
	 meta:
		 description = "Auriga | biscuit"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "6B31344B40E2AF9C9EE3BA707558C14E"

	 strings:

	 	$pdb = "\\drizt\\projects\\auriga\\branches\\stone_~1\\server\\exe\\i386\\riodrv32.pdb"

	 condition:
	 
	 	any of them
}
