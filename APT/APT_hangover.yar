rule apt_hanover_pdb
{
	 meta:

		 description = "Rule to detect hanover samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 date = "2012-01-05"
		 hash = "a2460412575cdc187dfb69eb2847c5b43156af7f7d94b71422e7f771e8adb51e"
		 hash = "397c6c71201aa7c2fc14ee1928144f85d1f7842b5c471bec5aa2dee42c4ce7d7"
		 hash = "4e66ba3e35fc5665cebf66a94c6ba833e391024c4270ef8cd56b374cc6f1cfbc"
		 hash = "ff12b3b1c623c201a1dfe9daf1eed1065c7e3714bd031cf1b5b75b0047112219"
		 hash = "9327054a9d5cf509c33bc170d925c201c4b97c420a32ed6dafcfcab74ef75975"
		 hash = "8893db5e27f952dd00e34a128f877bfb4ffc92eef7a8ad4c62dd0def470e96c2"
		 hash = "3d64a45e56ea2472a8cbf8df930efa64ab0418c2d3f4f92b49cada87be51f054"
		 hash = "9be0d0552a149b533d17645b46fb0e81190a1f6b9f397ba6832beddc345518c7"
		 hash = "c2c6eebb322a52b09e1dff22df103ee8caf0a438f0102eb78daa4d24e2510fa0"
		 hash = "7e2093c257499140e9410379ab54df6a5d4e88e4112187ae32bbd26c0dcff0ea"
		 hash = "8bbb63d18bd4b4d08f7441075670f8a73749ae550b59de034a6615ed6b449362"
		 hash = "354302e538ded150d97a3750be2a0a3b00b8cd5c80ab73816c7ea5c81ea0046e"
		 hash = "119af076d0907b68d547dfdf9b35e80226a3c8b2102e4a5571281d1093600e48"
		 hash = "0746a07537a701a671a16ecc980b059356ec9bd7aac31debc1277ce72b818f7b"
		 hash = "d7e7408bd1b3c89c9fc693fc9996e262c0b07827c2accefe1177257a063a5464"
		 

 	strings:

		$pdb = "\\andrew\\Key\\Release\\Keylogger_32.pdb"
		$pdb1 = "\\BACK_UP_RELEASE_28_1_13\\General\\KG\\Release\\winsvcr.pdb"
		$pdb2 = "\\BackUP-Important\\PacketCapAndUpload_Backup\\voipsvcr\\Release\\voipsvcr.pdb"
		$pdb3 = "\\BNaga\\kaam\\New_FTP_2\\Release\\ftpback.pdb"
		$pdb4 = "\\DD0\\DD\\u\\Release\\dataup.pdb"
		$pdb5 = "\\Documents and Settings\\Admin\\Desktop\\Newuploader\\Release\\Newuploader.pdb"
		$pdb6 = "\\Documents and Settings\\Admin\\Desktop\\Uploader Code\\Release\\Newuploader.pdb"
		$pdb7 = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		$pdb8 = "\\smse\\Debug\\smse.pdb"
		$pdb9 = "\\Users\\admin\\Documents\\Visual Studio 2008\\Projects\\DNLDR-no-ip\\Release\\DNLDR.pdb"
		$pdb10 = "\\final exe\\check\\Release\\check.pdb"
		$pdb11 = "\\Projects\\Elance\\AppInSecurityGroup\\FtpBackup\\Release\\Backup.pdb"
		$pdb12 = "\\projects\\windows\\MailPasswordDecryptor\\Release\\MailPasswordDecryptor.pdb"
		$pdb13 = "\\final project backup\\UPLODER FTP BASED\\New folder\\Tron 1.2.1(Ftp n Startup)\\Release\\Http_t.pdb"

 	condition:

 	uint16(0) == 0x5a4d and
 	filesize < 1000KB and
 	any of them
}

rule apt_hanover_appinbot_pdb
{
	 meta:

		 description = "Rule to detect hanover appinbot samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 date = "2012-01-05"
		 hash = "4e66ba3e35fc5665cebf66a94c6ba833e391024c4270ef8cd56b374cc6f1cfbc"
		 hash = "2eba41e4c16f0b8ce4e3670c7f6f8264519979f3838b6bf213c3074398eed7c7"
		 hash = "ceaeebb9d83181819a9bf6ceed215999519bd1afe23aa353c49dc9f744a127f8"
		 hash = "94c711b55676f5ca59e51bd4528a0a13646ce636853c4b3ab4e93d772d9fa928"
		 hash = "c575ad674c345a83b4bbc44ba3b646e52c0e717e8dc03860bfc6fd9a2feecc1c"
		 hash = "ba146251344f2dac8ea050a5d2fe3578dcdd3ca3339ad71cdc8e940305a35696"
		 hash = "b46be792d330c0bf88f9bc635dbbe5e4023f4111d80b5aabb675142c25d8d094"
		 hash = "6ad56d64444fa76e1ad43a8c260c493b9086d4116eb18af630e65d3fd39bf6d6"

	 strings:

		 $pdb = "\\BNaga\\backup_28_09_2010\\threads tut\\pen-backup\\BB_FUD_23\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb1 = "\\BNaga\\SCode\\BOT\\MATRIX_1.2.2.0\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb2 = "\\Documents and Settings\\Admin\\Desktop\\appinbot_1.2_120308\\appinclient\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb3 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb4 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\ MATRIX_1.3.4\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb5 = "\\Documents and Settings\\Administrator\\Desktop\\Backup\\17_8_2011\\MATRIX_1.3.4\\MATRIX_1.3.4\\ CLIENT\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb6 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb7 = "\\pen-backup\\Copy of client\\Copy of client\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb8 = "\\temp\\elance\\PROTOCOL_1.2\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb9 = "\\Users\\PRED@TOR\\Desktop\\appinbot_1.2_120308\\Build\\Win32\\Release\\deleter.pdb"
		 $pdb10 = "\\Users\\PRED@TOR\\Desktop\\MODIFIED PROJECT LAB\\admin\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb11 = "\\Desktop backup\\Copy\\appinbot_1.2_120308\\Build\\Win32\\Release\\appinclient.pdb"
		 $pdb12 = "\\Datahelp\\SCode\\BOT\\MATRIX_1.3.3\\CLIENT\\Build\\Win32\\Release\\appinclient.pdb"
 	
 	condition:

		uint16(0) == 0x5a4d and
	 	filesize < 440KB and
	 	any of them
}

rule apt_hanover_foler_pdb
{
	 meta:
		 description = "Rule to detect hanover foler samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 date = "2012-01-05"
		 hash = "b2fef273176494e16c108bec2ef17224b646ac006fe5dbc1ec9b454e352a9487"
		 hash = "01de97b656ddc26ce4ed0513f3e7b07e01c6c9e9331c80ad9f1ad3c141c36db1"
		 hash = "bd77d7f8af8329dfb0bcc0624d6d824d427fbaf859ab2dedd8629aa2f3b7ae0d"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb"
		 $pdb2 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\UsbP - u\\Release\\UsbP.pdb"
		 $pdb3 = "\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 480KB and
	 	any of them
}

rule apt_hanover_linog_pdb
{
	 meta:
		 description = "Rule to detect hanover linog samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 date = "2012-01-05"
		 hash = "9d03e61a18fcdde0b207ac6cc284fdd77d73f47fab2e3076b538b9b1bcfbbbd6"
		 hash = "f6319fd0e1d3b9d3694c46f80208e70b389e7dcc6aaad2508b80575c604c5dba"

	 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\Backup-HP-ABCD-PC\\download\\Release\\download.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 165KB and
	 	any of them
}

rule apt_hanover_ron_babylon_pdb
{
	 meta:
		 description = "apt_hanover_ron_babylon"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 date = "2012-01-05"
		 hash = "b77cfd1df763ef721e455d635a8a1d51b0d65b56a008b01ac0b0cb9977a3df2b"
		 hash = "1e33c0e6e72fece5f112b501b4e73df5fb4c7c99dedd75c56df67baf78a9a765"
		 hash = "26c4c04d763f0d1eba408821412ec805560fcce7436347af4ef2d6709f05a63d"
		 hash = "3e1b01e6ca8cfdb0097bd7208d55f5051eaba258626830af4ec76c1593911bdf"
		 hash = "33da331fabda5a63ab9f51aad3d5548c1bc602860923913aaf6b5b12fbde112e"
		 hash = "ce0b7f8ab3c630f798c737a343ea28766c5abb33edec7fa4d0217c270b288083"
		 hash = "61c2dbab2a90512689ac11e724bd8d2923a30780bfb9cac884ba4eb390e8fd40"
		 hash = "621a62137142d18637f2361ec46edfb1d380333e2c9cdc3d8aace922fefba4fc"
		 hash = "9e3fdb30de85f9b5ab7856e082cf7410e17e9602d647f5ad7ddaec3d7b5bc0ab"
		 hash = "110b8dea1ffcbec94a55f64ae2d830cdb3db7292dd468d3a151e0bf5c0fe968a"
		 hash = "ed158a0eb0a7c1451abfd7ea2e96ddcc93fb3908f86965e8ce4c339d0dc1556c"
		 hash = "ac4528ead85350280ece4311ae4f280550b84e77d7b14c7c352c028772f886fe"
		 hash = "670d054a59110f355ff331490a2cfbc54509af54e965548959a2053d7d237d26"
		 hash = "e165ea0eda2af4731e680a97a51dcd2cbb382569e8afa179f2eaeb86074486e9"
		 hash = "bf67f3dc5bc7e5fbfc040cdec410b76c486fbacfe433df3018a6a4ae7ef6bd87"
		 hash = "1a957fd82067e6ada61652f5118e02822b50dbb515e13048609a3415bec49d22"
		 hash = "8f15d2c3cd2e8a46cd5046cea5eb6fc9d28f0a69d452fbd2a39dab5c9906c833"
		 hash = "527ef4c44bd35b6763c6b3f46acb887198f1232d15aa1cd83d7d9c6e790d3d6c"
		 hash = "c04dda062d51f5230efbbcdd8bd19db2340787bd81fc43a891f2f26a4d58a4c1"
		 hash = "82a93e80620a33497c7028471b7836d23cbb86c0d99414a31ed378a5422aca22"
		 hash = "5d1f5a384a756a8a5659b78cbb1fc815b75be9063fa34b9ae938825fc34ad0fb"
		 hash = "632cfe00176024de8833d9054b049c4657e84f99efa22ce2a2b162a875e8298e"
		 hash = "3140c7defd7885a562b21bf0a6dbb82f387734810af69c15378ddb5b3c6f8430"
		 hash = "32696554015d6433b2ec8155bfad3e6519530ca89226724f5ac257f5c6135763"
		 hash = "c07f389ff3ae830ae41294a376f362f08364deb9890bdaf634971a4e0c68a5a3"
		 hash = "7fdace59ba9f8cd15a21e5b34bef75f153cfd0f5976e5cee14065544ac434d0c"
		 hash = "426915994bcf56048e67a87100ac44e44244d6ecb317d8407a266e3bc6a42479"
		 hash = "a395f3117130be7b870cc14ced1c4000dabcd433da4093f5806ab3d077a1a5fc"
		 hash = "a0ce7ed257fcb4ec385638a869c0ce0592371e0503762a3aeddde34ff182e962"
		 hash = "228ec161435b8f8a450ffe179219ca8c4df2d1ed3b351112be366d6efa38f559"
		 hash = "d06f6b6a1ca7f3f2453d6f91026b9089362db2e676fbd3a02d04662f6c449084"
		 hash = "eac43784d9ba3bad1ee431ad1f3b8e84ef65103376a2622e48b1443765d8fca6"
		 hash = "c64983cae54119ef9c13f30147505eae1b05417f2770cf57539e0e7f4be39752"
		 hash = "1620c24b7a983778c36cbf5ef065ccd67f2c1c0b8919f78e5fe63ead133a4708"
		 hash = "19941eea349d1573cdaff91c22820e02b61064f360411bc35e09770ad0403920"
		 hash = "8d53d15740e89db21250aae47d9000a47cc247f38931196b5646ec9309ed17a1"
		 hash = "38dd63e1ef9952bb89d0fa9af86f9c2f37573b16f2f17ddfc5e3ec19bb462fb6"
		 hash = "a93b70f827d4a48fcbbd6c9018306fa37de95e4a7a32d5d6d47f44b52769c94b"
		 hash = "a8d521cc23c0383559f6ed5d3d7e320b1bee43a6ffdcabbff4053c6441538e8b"
		 hash = "0feadf86df99be0fdaa52ea84166bef6d3a2f5fd6b9c07341f996aba88406c8e"
		 hash = "1d5803df744ace3e078e689909bb4e1714f783bc0113c231dad8f67d3b28132f"
		 hash = "9a88eeb3d2f284fb81049b55acbed030f9b89288fcac90a67969f36b5534b466"
		 hash = "56b57ecc361154d070849ad3ea11589a2f9ebce1eab5e7993be5e4a322b3ade9"
		 hash = "6bc0e722060b544ced0d0aed81b5809255971f50acc897e3220cf9d299f0445a"
		 hash = "784cfb1bfdd7080c658fad08b1f679bbb0c94e6e468a3605ea47cdce533df815"
  
 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\26_10_2010\\demoMusic\\Release\\demoMusic.pdb"
		 $pdb2 = "\\26_10_2010\\New_FTP_HttpWithLatestfile2\\Release\\httpbackup.pdb"
		 $pdb3 = "\\26_10_2010\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\FirstBloodA1.pdb"
		 $pdb4 = "\\app\\Http_t\\Release\\Crveter.pdb"
		 $pdb5 = "\\BNaga\\kaam\\Appin SOFWARES\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb6 = "\\BNaga\\kaam\\kaam\\NEW SOFWARES\\firstblood\\Release\\FirstBloodA1.pdb"
		 $pdb7 = "\\BNaga\\kaam\\kaam\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\Ron.pdb"
		 $pdb8 = "\\BNaga\\kaam\\New_FTP_HttpWithLatestfile2_FirstBlood_Released\\ New_FTP_HttpWithLatestfile2\\Release\\FirstBloodA1.pdb"
		 $pdb9 = "\\BNaga\\My Office kaam\\Appin SOFWARES\\HTTP\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb10 = "\\Documents and Settings\\abc\\Desktop\\Dragonball 1.0.2(WITHOUT DOWNLOAD LINK)\\Release\\Ron.pdb"
		 $pdb11 = "\\Documents and Settings\\Administrator\\Desktop\\Feb 2012\\kmail(httpform1.1) 02.09\\Release\\kmail.pdb"
		 $pdb12 = "\\MNaga\\My Office kaam\\Appin SOFWARES\\HTTP\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb13 = "\\N\\kl\\Release\\winlsa.pdb"
		 $pdb14 = "\\N\\sr\\Release\\waulct.pdb"
		 $pdb15 = "\\Release\\wauclt.pdb"
		 $pdb16 = "\\Users\\neeru rana\\Desktop\\Klogger- 30 may\\Klogger- 30 may\\Release\\Klogger.pdb"
		 $pdb17 = "\\december task backup\\TRINITY PAYLOAD\\Dragonball 1.0.0(WITHOUT DOWNLOAD LINK)\\Release\\Ron.pdb"
		 $pdb18 = "\\Documents and Settings\\appin\\Desktop\\New_FTP_1\\New_FTP_1\\Release\\HTTP_MyService.pdb"
		 $pdb19 = "\\May Payload\\new keylogger\\Flashdance1.0.2\\kmail(http) 01.20\\Release\\kmail.pdb"
		 $pdb20 = "\\Monthly Task\\September 2011\\HangOver 1.3.2 (Startup)\\Release\\Http_t.pdb"
		 $pdb21 = "\\Sept 2012\\Keylogger\\Release\\Crveter.pdb"
		 $pdb22 = "\\Datahelp\\keytest1\\keytest\\taskmng.pdb"
		 $pdb23 = "\\Datahelp\\UPLO\\HTTP\\HTTP_T\\17_05_2011\\Release\\Http_t.pdb"
		 $pdb24 = "\\Datahelp\\UPLO\\HTTP\\HTTP_T\\20_05_2011\\Release\\Http_t.pdb"
		 $pdb25 = "\\June mac paylods\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\Klogger.pdb"
		 $pdb26 = "\\June mac paylods\\Keylo ger backup\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\kquant.pdb"
		 $pdb27 = "\\June mac paylods\\Keylogger backup\\final Klogger-1 june-Fud from eset5.0\\Klogger- 30 may\\Klogger- 30 may\\Release\\kquant.pdb"
		 $pdb28 = "\\My\\lan scanner\\Task\\HangOver 1.2.2\\Release\\Http_t.pdb"
		 $pdb29 = "\\New folder\\paylod backup\\OTHER\\Uploder\\HangOver 1.5.7 (Startup)\\HangOver 1.5.7 (Startup)\\Release\\Http_t.pdb"
		 $pdb30 = "\\keyloger\\KeyLog\\keytest1\\keytest\\taskmng.pdb"
		 $pdb31 = "\\august\\13 aug\\HangOver 1.5.7 (Startup) uploader\\Release\\Http_t.pdb"
		 $pdb32 = "\\backup E\\SourceCodeBackup\\september\\aradhana\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb33 = "\\payloads\\new backup feb\\SUNDAY\\kmail(http) 01.20\\kmail(http) 01.20\\Release\\kmail.pdb"
		 $pdb34 = "\\payloads\\ita nagar\\Uploader\\HangOver 1.5.7 (Startup)\\HangOver 1.5.7 (Startup)\\Release\\Http_t.pdb"
		 $pdb35 = "\\final project backup\\task information\\task of september\\Tourist 2.4.3 (Down Link On Resource) -L\\Release\\Ron.pdb"
		 $pdb36 = "\\final project backup\\complete task of ad downloader & usb grabber&uploader\\New folder\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb37 = "\\final project backup\\uploader version backup\\fud all av hangover1.5.4\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb38 = "\\final project backup\\uploader version backup\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb39 = "\\New folder\\with icon +shortcut link\\HangOver 1.5.3 (Startup)\\Release\\Http_t.pdb"
		 $pdb40 = "\\Http uploader limited account\\Http uploader limited account\\RON 2.0.0\\Release\\Ron.pdb"
		 $pdb41 = "\\Uploader\\HTTP\\HTTP Babylon 5.1.1\\HTTP Babylon 5.1.1\\Httpbackup\\Release\\HttpUploader.pdb"
		 $pdb42 = "\\Uploader\\HTTP\\ron uplo\\RON 2.0.0\\Release\\Ron.pdb"

 	condition:

 		uint16(0) == 0x5a4d and
	 	filesize < 330KB and
	 	any of them
}

rule apt_hanover_slidewin_pdb
{
	 meta:

		 description = "Rule to detect hanover slidewin samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 reference = "https://securityaffairs.co/wordpress/14550/cyber-crime/operation-hangover-indian-cyberattack-infrastructure.html"
		 date = "2012-01-05"
		 hash = "676bb8fee61b083f6668582b40b1f3c177707cb0b6e8cfbc442714ee3ff9710a"
		 hash = "0741a7e7bde5ec56834e66a9bea3d985e8b67f75c5bc86792c78b194869c91cd"
		 hash = "d3830ea4509152b2c569df21dbedf3e925042bd8d390bddeada4b8d6685dcdc4"
		 hash = "89b80267f9c7fc291474e5751c2e42838fdab7a5cbd50a322ed8f8efc3d2ce83"

	 strings:

		 $pdb = "\\Users\\God\\Desktop\\ThreadScheduler-aapnews-Catroot2\\Release\\ThreadScheduler.pdb"
		 $pdb1 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-hostzi\\Release\\slidebar.pdb"
		 $pdb2 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-spectram\\Release\\slidebar.pdb"
		 $pdb3 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-zendossier\\Release\\slidebar.pdb"

	 condition:

	 	uint16(0) == 0x5a4d and
	 	filesize < 100KB and
	 	any of them
}
