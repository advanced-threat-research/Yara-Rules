import "androguard"

rule CLICKER_android_Clicker_G
{
	meta:

		description = "This rule try to detects Clicker.G samples"
		author = "Jacob Soo Lead Re"
		date = "2016-07-01"
        rule_version = "v1"
        malware_type = "Clicker"
        malware_family = "Clicker:Android/Clicker"
        actor_type = "Cybercrime"
        actor_group = "Unknown"	
		reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-clicker-dgen-found-google-play/"
	
	strings:

		$a = "upd.php?text="

	condition:
	
		androguard.receiver(/MyBroadCastReceiver/i) and $a
}
