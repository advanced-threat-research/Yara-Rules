rule BackdoorFCKG: CTB_Locker_Ransomware
{

meta:

	author = "ISG"
	date = "2015-01-20"
	reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
	description = "CTB_Locker"

strings:

	$string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	$stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
	$string2 = "keme132.DLL" 
	$string3 = "klospad.pdb" 

condition:

	3 of them 
}