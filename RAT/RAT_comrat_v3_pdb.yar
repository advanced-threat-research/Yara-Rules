rule rat_comrat 
{
	 meta:
		 description = "Rule to detect the ComRAT RAT"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "28dc1ca683d6a14d0d1794a68c477604"
	 
	 strings:

	 	$pdb = "\\projects\\ChinckSkx64\\Debug\\Chinch.pdb"

	 condition:
	 
	 	any of them
}
