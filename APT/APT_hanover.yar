rule apt_hanover_pdb
{
	 meta:
	 description = "Rule to detect hanover samples based on PDB"
	 author = "Marc Rivero | McAfee ATR Team"
	 hash = "32C0785EDD5C9840F55A8D40E53ED3D9"
	 hash = "0BBE6CAB66D76BAB4B44874DC3995D8F"
	 hash = "350AD4DB3BCACF3C15117AFDDF0BD273"
	 hash = "158FF697F8E609316E2A9FBE8111E12A"
	 hash = "24874938F44D34AF71C91C011A5EBC45"
	 hash = "3166C70BF2F70018E4702673520B333B"
	 hash = "FE2CBAB386B534A10E71A5428FDE891A"
	 hash = "4A06163A8E7B8EEAE835CA87C1AB6784"
	 hash = "C7CB3EC000AC99DA19D46E008FD2CB73"
	 hash = "2D7D9CB08DA17A312B64819770098A8E"
	 hash = "74125D375B236059DC144567C9481F2A"
	 hash = "EDDD399D3A1E3A55B97665104C83143B"
	 hash = "54435E2D3369B4395A336389CF49A8BE"
	 hash = "232F616AD81F4411DD1806EE3B8E7553"
	 hash = "645801262AEB0E33D6CA1AF5DD323E25"
	 

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

 	any of them
}

rule apt_hanover_appinbot_pdb
{
	 meta:

		 description = "Rule to detect hanover appinbot samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "350AD4DB3BCACF3C15117AFDDF0BD273"
		 hash = "49527C54A80E1BA698E0A8A7F7DD0A7D"
		 hash = "36B3F39E7A11636ADB29FE36BEA875C4"
		 hash = "BB9974D1C3617FCACF5D2D04D11D8C5A"
		 hash = "4F82A6F5C80943AF7FACFCAFB7985C8C"
		 hash = "4F82A6F5C80943AF7FACFCAFB7985C8C"
		 hash = "549FED3D2DD640155697DEF39F7AB819"
		 hash = "549FED3D2DD640155697DEF39F7AB819"
		 hash = "36B3F39E7A11636ADB29FE36BEA875C4"
		 hash = "3FD48F401EDF2E20F1CA11F3DAE3E2EF"
		 hash = "3FD48F401EDF2E20F1CA11F3DAE3E2EF"
		 hash = "8A4F2B2316A7D8D1938431477FEBF096"
		 hash = "5BDA43ED20EA6A061E7332E2646DDC40"

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

		any of them
}

rule apt_hanover_foler_pdb
{
	 meta:
		 description = "Rule to detect hanover foler samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "07DEFD4BDA646B1FB058C3ABD2E1128E"
		 hash = "01A7AF987D7B2F6F355E37C8580CB45A"
		 hash = "118716061197EBCDAE25D330AEF97267"
		 hash = "01A7AF987D7B2F6F355E37C8580CB45A"

	 strings:

		 $pdb = "\\Documents and Settings\\Administrator\\Desktop\\nn\\Release\\nn.pdb"
		 $pdb1 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\Release\\UsbP.pdb"
		 $pdb2 = "\\Documents and Settings\\Administrator\\Desktop\\UsbP\\UsbP - u\\Release\\UsbP.pdb"
		 $pdb3 = "\\Monthly Task\\August 2011\\USB Prop\\Usb Propagator.09-24\\nn\\Release\\nn.pdb"

	 condition:

	 	any of them
}

rule apt_hanover_linog_pdb
{
	 meta:
		 description = "Rule to detect hanover linog samples based on PDB"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "16C140FB61B6D22E02AA2B04748B5A34"
		 hash = "8B1A208216613BF0B931252A98D5E2B8"

	 strings:

		 $pdb = "\\Users\\hp\\Desktop\\download\\Release\\download.pdb"
		 $pdb1 = "\\Backup-HP-ABCD-PC\\download\\Release\\download.pdb"

	 condition:

	 	any of them
}

rule apt_hanover_ron_babylon_pdb
{
	 meta:
		 description = "apt_hanover_ron_babylon"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "4B9F8CB4D87672611F11ACBE3E204249"
		 hash = "9073B3DB88720A555AC511956A11ABF4"
		 hash = "4B9F8CB4D87672611F11ACBE3E204249"
		 hash = "81F84B1BDF6337A6E9C67BE2F51C50E0"
		 hash = "E3CF3B1D2A695B9B5046692A607C8B30"
		 hash = "80FBEBA3DA682570C4DB0482CD61B27D"
		 hash = "0F98B7D1E113E5194D62BC8F20720A6B"
		 hash = "376A0ED56366E4D35CECFCDBD70204B0"
		 hash = "33840EE0B45F31081393F4462FB7A5B6"
		 hash = "423519AE6C222AB54A2E82104FA45D12"
		 hash = "0B88F197B4266E6B78EA0DCB9B3496E9"
		 hash = "9E05D3F072469093542AFDDB1C2E874E"
		 hash = "118ED6F8AA3F01428A95AE7BA8EF195C"
		 hash = "5433804B7FC4D71C47AA2B3DA64DB77D"
		 hash = "555D401E2D41ED00BC9436E3F458B52E"
		 hash = "32D461D46D30C5D7C3F8D29DD0C8A8C4"
		 hash = "7E74334C1495A3F6E195CE590C7D42E5"
		 hash = "F6AB2B8ADBB2EB8A5D2F067841B434EF"
		 hash = "331DB34E5F49AC1E318DDA2D01633B43"
		 hash = "89D9851C162B98DB2C7A2B4F6A841B2A"
		 hash = "DE81F0BDBD0EF134525BCE20B05ED664"
		 hash = "0FBC01C38608D1B5849BF47492148588"
		 hash = "4921C4C5CDD58CA32C5E957B63CF06CD"
		 hash = "7244AAA1497D16E101AD1B6DEE05DFE3"
		 hash = "5BC2744A40A333DC089AC04B6D71154E"
		 hash = "0128F683E508C807EC76D5092EAAF22C"
		 hash = "B48C2E42514AE1395E28FC94F6C8A6F1"
		 hash = "A487E68A4C7EC11EBFF428BECC64A06C"
		 hash = "E5479FAC44383CA1998EB416AA2128F0"
		 hash = "30A920F8C9B52AA8C68501F502E128EB"
		 hash = "FC0F714D16B1A72FCC6719151E85A8F0"
		 hash = "9BCB294ECFBEBFF744E2A50B3F7099E6"
		 hash = "0E9E46D068FEA834E12B2226CC8969FD"
		 hash = "1CE331F0D11DC20A776759A60FB5B3F5"
		 hash = "26FE2770B4F0892E0A24D4DDDBBFE907"
		 hash = "C814E35D26848F910DD5106B886B9401"
		 hash = "EEEF49FDB64A03A0C932973F117F9056"
		 hash = "A8CAF03B50C424E9639580CDCC28507B"
		 hash = "A1F8595D6D191DCBED3D257301869CE9"
		 hash = "EA9BFC25FC5BDC0B1B96F7B2AF64F1AC"
		 hash = "153AC7591B9326EE63CD36180D39665E"
		 hash = "37448F390F10ECCF5745A6204947203A"
		 hash = "770FC76673C3C2DAADD54C7AA7BA7CC3"
		 hash = "BA790AC25BB9C3C6259FDFF8DCE07E5A"
		 hash = "135A18C858BFDC5FC660F15D6E1FB147"
		 hash = "D8DCF2A53505A61B5915F7A1D7440A2E"
 
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

 		any of them
}

rule apt_hanover_slidewin_pdb
{
	 meta:

		 description = "Rule to detect hanover slidewin samples"
		 author = "Marc Rivero | McAfee ATR Team"
		 hash = "32DD4DEBED737BF2692796E6DCA7D115"
		 hash = "97BDE23AE78DDABC36A0A46A4E5B1FAE"
		 hash = "CB22FB4E06F7D02F8CAC1350D34CA0A6"
		 hash = "34B013D36146BA868E4DFA51529C47A4"

	 strings:

		 $pdb = "\\Users\\God\\Desktop\\ThreadScheduler-aapnews-Catroot2\\Release\\ThreadScheduler.pdb"
		 $pdb1 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-hostzi\\Release\\slidebar.pdb"
		 $pdb2 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-spectram\\Release\\slidebar.pdb"
		 $pdb3 = "\\Data\\User\\MFC-Projects\\KeyLoggerWin32-zendossier\\Release\\slidebar.pdb"

	 condition:

	 	any of them
}
