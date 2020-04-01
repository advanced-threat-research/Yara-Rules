rule apt_turla_pdb
{
	 meta:

		 description = "Rule to detect a component of the APT Turla"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://attack.mitre.org/groups/G0010/"
		 date = "2017-05-31"
		 hash = "3b8bd0a0c6069f2d27d759340721b78fd289f92e0a13965262fea4e8907af122"
	 
	 strings:

	 	$pdb = "\\Workshop\\Projects\\cobra\\carbon_system\\x64\\Release\\carbon_system.pdb"

	 condition:
	 
	 	uint16(0) == 0x5a4d and
 		filesize < 650KB and
 		any of them
}
