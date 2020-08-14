rule RAT_spygate_v2_9
{
	meta:

		description = "Spygate v2.9 Remote Access Trojan"
		date = "2014/09"
        rule_version = "v1"
        malware_type = "rat"
        malware_family = "Rat:W32/SpyGate"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"
		
	
	strings:

		$1 = "shutdowncomputer" wide
		$2 = "shutdown -r -t 00" wide
		$3 = "blockmouseandkeyboard" wide
		$4 = "ProcessHacker"
		$5 = "FileManagerSplit" wide
	
	condition:
	
		all of them
}
