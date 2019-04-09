rule apt_babar_pdb
{
	 meta:
		 description = "APT Babar"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "9FFF114F15B86896D8D4978C0AD2813D"

	 strings:

	 	$pdb = "\\Documents and Settings\\admin\\Desktop\\Babar64\\Babar64\\ obj\\DllWrapper Release\\Release.pdb"

	 condition:
	 
	 	any of them
}
