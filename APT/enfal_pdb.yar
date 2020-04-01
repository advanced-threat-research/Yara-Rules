rule enfal_pdb
{
	 meta:

		 description = "Rule to detect Enfal malware"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/enfal"
		 date = "2013-08-27"
		 hash = "6756808313359cbd7c50cd779f809bc9e2d83c08da90dbd80f5157936673d0bf"
		 hash = "8a038cf6cef7e062d707b50ae20700353fbd7c0d7328f874232cefeb73c99463"
		 hash = "b56821058103588b242e907451a7f7f5b980ee4b62b648e6197526feae0c8f3c"
		 hash = "fba718556c1ef52c85ac1b8a889148af054a2b0ecc3b22ce02f6a2f460fc65d0"
		 hash = "83d7572998462b4054bd7c6ce6e7e79f1f991085b92a2f97df6d7e14598de53a"
		 hash = "fbc31266f78ab9d50e7b135803db3d24bc1fb0b0c91a0289157a3e3d7fce1e3d"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\DllServiceTrojan.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\My Documents\\Work\\EtenFalcon\\Release\\ServiceDll.pdb"
		 $pdb2 = "\\Release\\ServiceDll.pdb"
		 $pdb3 = "\\muma\\0511\\Release\\ServiceDll.pdb"
		 $pdb4 = "\\programs\\LuridDownLoader\\LuridDownloader for Falcon\\ServiceDll\\Release\\ServiceDll.pdb"
	 
	 condition:

	 	uint16(0) == 0x5a4d and
 		filesize < 150KB and
 		any of them
}
