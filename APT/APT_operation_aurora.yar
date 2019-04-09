rule apt_aurora_pdb_samples
{
	 meta:
	 description = "Aurora APT Malware 2006-2010"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "467EEF090DEB3517F05A48310FCFD4EE"
	 hash = "4A47404FC21FFF4A1BC492F9CD23139C"
	 
 strings:

	 $pdb = "\\AuroraVNC\\VedioDriver\\Release\\VedioDriver.pdb"
	 $pdb1 = "\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"
 
 condition:
 
 	any of them
}
