rule apt_miniasp_pdb {
	 
	 meta:
	 
		 description = "Rule to detect MiniASP based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf"
		 date = "2012-07-12"
		 hash = "8d180d59da135e447d01d4bda60de6318b656622b8ec9653b53d58cf9214f63b"
		 hash = "42334f2119069b8c0ececfb14a7030e480b5d18ca1cc35f1ceaee847bc040e53"
		 
	 strings:
		 
		 $pdb = "\\Project\\mm\\Wininet\\Attack\\MiniAsp4\\Release\\MiniAsp.pdb"
		 $pdb1 = "\\XiaoME\\AiH\\20120410\\Attack\\MiniAsp3\\Release\\MiniAsp.pdb"
	 
	 condition:

	 	uint16(0) == 0x5a4d and
 		filesize < 80KB and
 		any of them
}
