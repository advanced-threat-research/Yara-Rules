rule apt_hikit_rootkit
{
	 meta:
		 description = "Rule to detect the rootkit hikit based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 
	 strings:

		 $pdb = "\\JmVodServer\\hikit\\bin32\\RServer.pdb"
		 $pdb1 = "\\JmVodServer\\hikit\\bin32\\w7fw.pdb"
		 $pdb2 = "\\JmVodServer\\hikit\\bin32\\w7fw_2k.pdb"
		 $pdb3 = "\\JmVodServer\\hikit\\bin64\\w7fw_x64.pdb"

	 condition:

	 	any of them
}
