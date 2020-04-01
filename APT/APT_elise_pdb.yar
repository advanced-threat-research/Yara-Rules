rule apt_elise_pdb {
	 
	 meta:

		 description = "Rule to detect Elise APT based on the PDB reference"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://attack.mitre.org/software/S0081/"
		 date = "2017-05-31"
		 hash = "371b158e95a1d00aea735522794c41cd4bef75365413c4189d6ed252e9b4aba5"
	     hash = "f2fb4f42e978f6f15005699cba3fa6515abf81713b64253d9fd06c993b586c26"
	     hash = "af484f57a33a54644618698d247740d0392bf21f8c00a8a802521692ec6d4255"
	     hash = "114301b5f0982ce74faf9fc99da92a7b19a68545dfc55fd88c533cd46aa8600e"
	     hash = "b426dbe0f281fe44495c47b35c0fb61b28558b5c8d9418876e22ec3de4df9e7b"
	
	 strings:

		 $pdb = "\\lstudio\\projects\\lotus\\elise\\Release\\EliseDLL\\i386\\EliseDLL.pdb"
		 $pdb1 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\SetElise.pdb"
		 $pdb2 = "\\lstudio\\projects\\lotus\\elise\\Release\\SetElise\\i386\\SetElise.pdb"
		 $pdb3 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\Uninstaller.pdb"
		 $pdb4 = "\\lstudio\\projects\\lotus\\evora\\Release\\EvoraDLL\\i386\\EvoraDLL.pdb"

	 condition:

	  uint16(0) == 0x5a4d and 
      filesize < 50KB and 
      any of them
}
