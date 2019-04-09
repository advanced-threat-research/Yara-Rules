rule apt_gdocupload_glooxmail
{
	 meta:
		 description = "Rule to detect the tool gdocupload based on the PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "232D1BE2D8CBBD1CF57494A934628504"

	 strings:

	 	$pdb = "\\Project\\mm\\Webmail\\Bin\\gdocs.pdb"

	 condition:

	 	any of them
}
