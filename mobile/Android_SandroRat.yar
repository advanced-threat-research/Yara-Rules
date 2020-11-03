import "androguard"


rule MOBILE_sandrorat
{
	meta:

            description = "This rule detects SandroRat"
	    author = "Jacob Soo Lead Re"
	    date = "2016-05-21"
            rule_version = "v1"
            malware_type = "rat"
            malware_family = "Rat:Android/SandroRat"
            actor_type = "Cybercrime"
            actor_group = "Unknown"
	    reference = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"

	condition:
	    androguard.activity(/net.droidjack.server/i) 
}
