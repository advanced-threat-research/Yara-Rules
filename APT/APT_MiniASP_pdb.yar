rule MiniASP_PDB
{
	 meta:
		 description = "Rule to detect MiniASP based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "026C1532DB8125FBAE0E6AA1F4033F42"
		 hash = "77FBFED235D6062212A3E43211A5706E"
		 
	 strings:
		 $pdb = "\\Project\\mm\\Wininet\\Attack\\MiniAsp4\\Release\\MiniAsp.pdb"
		 $pdb1 = "\\XiaoME\\AiH\\20120410\\Attack\\MiniAsp3\\Release\\MiniAsp.pdb"
	 
	 condition:

	 	any of them
}
