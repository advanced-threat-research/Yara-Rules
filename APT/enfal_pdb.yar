rule enfal_pdb
{
	 meta:

		 description = "Rule to detect Enfal malware"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "D1B8DC41EFE4208191C766B303793D15"
		 hash = "A36CD4870446B513E70F903A77754B4F"
		 hash = "E7F93C894451EF1FDEFA81C6B229852C"
		 hash = "A3A6B5867A48DB969ABA90DD39771370"
		 hash = "01A0C09E9B3013C00009DA8D4E9E2B2B"
		 hash = "7A1D4CBA9CE2A28EF586C27689B5AEA7"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\DllServiceTrojan.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\ServiceDll.pdb"
		 $pdb2 = "\\Release\\ServiceDll.pdb"
		 $pdb3 = "\\muma\\0511\\Release\\ServiceDll.pdb"
		 $pdb4 = "\\programs\\LuridDownLoader\\LuridDownloader for Falcon\\ServiceDll\\Release\\ServiceDll.pdb"
	 
	 condition:

	 	any of them
}
