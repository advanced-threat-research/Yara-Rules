rule lagulon_trojan_pdb
{
	 meta:
	 description = "Rule to detect trojan Lagulon based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "e8b1f23616f9d8493e8a1bf0ca0f512a"

 strings:

 	$pdb = "\\proj\\wndTest\\Release\\wndTest.pdb"

 condition:

 	any of them
}
