rule elise_apt_pdb
{
	 meta:

	 description = "Rule to detect Elise APT based on the PDB reference"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "6F81C7AF2A17ECE3CF3EFFC130CE197A"
	 hash = "46877B923AE292C1E7C66E4F6F390AF7"
	 hash = "268A4D1679AE0DA89AB4C16A3A89A8F1"
	 hash = "A17CDAF23A84A3E410852B18BF5A47CD"
	 hash = "36BB0B614D9118679A635735E53B32AB"
	
	 strings:

		 $pdb = "\\lstudio\\projects\\lotus\\elise\\Release\\EliseDLL\\i386\\EliseDLL.pdb"
		 $pdb1 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\SetElise.pdb"
		 $pdb2 = "\\lstudio\\projects\\lotus\\elise\\Release\\SetElise\\i386\\SetElise.pdb"
		 $pdb3 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\Uninstaller.pdb"
		 $pdb4 = "\\lstudio\\projects\\lotus\\evora\\Release\\EvoraDLL\\i386\\EvoraDLL.pdb"

	 condition:

	 	any of them
}
