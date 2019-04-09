import "androguard"

rule Android_Clicker_G
{
	meta:

		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Clicker.G samples"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/"
	
	strings:

		$a = "upd.php?text="

	condition:
	
		androguard.receiver(/MyBroadCastReceiver/i) and $a
}
