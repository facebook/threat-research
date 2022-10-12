rule hilal_rat_dex {
	meta:
		source = "Facebook"
		date = "2022-04-07"
		description = "Detects custom android rat impersonating various applications that siphons phone details to a C2."
		reference = "https://about.fb.com/news/2022/04/metas-adversarial-threat-report-q1-2022/"
	strings:
		$class0 = "Lcom/hilal/SysUpdater/MainActivity;"
		$class1 = "Lcom/hilal/adm/R;"
		$file0 = "cacaca.dat"
		$file1 = "ccc.dat"
		$file2 = "fifi.dat"
		$file3 = "smr.dat"
		$file4 = "smse.dat"
		$typo0 = "Erron in Decryption"
		$typo1 = "GetDevcie"
		$sec1 = "6123cc12ef9bd0bf1592c69bf769853fb0a00084" // AES key
		$cmd0 = "/Aud"
		$cmd1 = "/Cam"
		$cmd2 = "/Upd"
		$cmd3 = "/Con"
		$func1 = "CamStart"
		$func2 = "AudStop"
		$func3 = "AudStart"
		$func4 = "DownFi"
		$func5 = "ScrSht"
		$func6 = "CamList"
		$func7 = "CamStop"
		$func8 = "ListExplore"
		$interesting_string0 = "isMyServiceRunning?"
		$interesting_string1 = "Checking new version... Please wait..."
		$notification_service0 = "********** onNotificationPosted"
		$notification_service1 = "********** onNOtificationRemoved"
		$phnum = "PhNumber"
	condition:
		(uint32be(0) == 0x6465780a or uint32be(0) == 0x6465790a) and // dex\n or dey\n
    	uint8(7) == 0x00 and // version must end in a null byte
		10 of them
		or all of ($file*)
		or all of ($func*)
		or all of ($interesting_*) and all of ($notification_*)
}
