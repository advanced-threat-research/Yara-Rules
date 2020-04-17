import "androguard"
import "cuckoo"

rule pwndroid5_downloader {

    meta:
    
        description = "Rule to detect the downloader pwndroid5"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "64424a7c5f0d8e1c5d64c4c6fa9bdc2987dbdcf1bafdb6f45df9e783712c5187"

	condition:

		androguard.activity("com.m.video.player.MainActivity") and 
		androguard.app_name("Adobe Flash Player") and 
		androguard.certificate.sha1("054F60BC818AEB1D3B8012C8FA1C20DCC4AE3642") and 
		androguard.displayed_version("1.0") and 
		androguard.filter("android.intent.action.USER_PRESENT") and 
		androguard.functionality.run_binary.class(/Lcom\/m\/video\/player\/MainApplication\;/) and 
		androguard.functionality.run_binary.code(/invoke\-static\ v0\,\ Ljava\/lang\/System\;\-\>loadLibrary\(Ljava\/lang\/String\;\)V/) and 
		androguard.functionality.run_binary.method(/\<clinit\>/) and 
		androguard.number_of_activities == 1 and 
		androguard.number_of_filters == 2 and 
		androguard.number_of_permissions == 7 and 
		androguard.number_of_receivers == 1 and 
		androguard.number_of_services == 1 and 
		androguard.package_name("com.m.video.player") and 
		androguard.permission("android.permission.ACCESS_NETWORK_STATE") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.READ_PHONE_STATE") and 
		androguard.permission("android.permission.WAKE_LOCK") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.receiver("com.m.video.BkReceiver") and 
		androguard.service("com.m.video.BkService") and 
		cuckoo.network.dns_lookup("alog.umeng.co") and 
		cuckoo.network.dns_lookup("app.appleadwords.net")
}
 
rule pwndroid5_downloader_certificate {

    meta:
    
        description = "Rule to detect the downloader pwndroid5 based on the certificate"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-04-17"
        reference = "https://www.blackberry.com/content/dam/blackberry-com/asset/enterprise/pdf/direct/report-bb-decade-of-the-rats.pdf"
        hash = "64424a7c5f0d8e1c5d64c4c6fa9bdc2987dbdcf1bafdb6f45df9e783712c5187"

	condition:

		androguard.activity("com.m.video.player.MainActivity") and 
		androguard.app_name("Adobe Flash Player") and 
		androguard.certificate.sha1("054F60BC818AEB1D3B8012C8FA1C20DCC4AE3642") and 
		androguard.displayed_version("1.0") and 
		androguard.number_of_permissions == 7 and 
		androguard.package_name("com.m.video.player") and 
		androguard.permission("android.permission.ACCESS_WIFI_STATE") and 
		androguard.permission("android.permission.CHANGE_WIFI_STATE") and 
		androguard.permission("android.permission.INTERNET") and 
		androguard.permission("android.permission.WRITE_EXTERNAL_STORAGE") and 
		androguard.receiver("com.m.video.BkReceiver") and 
		cuckoo.network.dns_lookup("alog.umeng.co") and 
		cuckoo.network.dns_lookup("app.appleadwords.net")
}
 
