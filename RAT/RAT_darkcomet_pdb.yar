rule DarkcometRAT_PDB
{
	 meta:
	 description = "Rle to detect an old DarkcometRAT based on the PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "6A659FB586F243C5FB12B780F5F00BFE"

	 strings:

	 	$pdb = "\\Users\\MY\\AppData\\Local\\TemporaryProjects\\Chrome\\obj\\x86\\Debug\\Chrome.pdb"

	 condition:

	 	any of them
}
