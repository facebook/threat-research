rule xploitspy_rat {
	meta:
		source = "Facebook"
		date = "2022-08-04"
		description = "Android RAT found on GitHub at https://github.com/XploitWizer/XploitSPY/tree/master/client/app/src/main/java/com/remote/app."
		reference = "https://about.fb.com/news/2022/08/metas-adversarial-threat-report-q2-2022/"
	strings:
		$func0 = "0xAU"
		$func1 = "0xCL"
		$func2 = "0xCO"
		$func3 = "0xFI"
		$func4 = "0xGP"
		$func5 = "0xIN"
		$func6 = "0xLO"
		$func7 = "0xMI"
		$func8 = "0xPM"
		$func9 = "0xSM"
		$func10 = "0xWI"
		$func11 = "0xCB"
		$func12 = "0xNO"
		$applist0 = "appName"
		$applist1 = "packageName"
		$applist2 = "versionName"
		$applist3 = "versionCode"
		$notif0 = "appName"
		$notif1 = "postTime"
	condition:
		7 of ($func*) and (
			all of ($applist*)
			or all of ($notif*)
		)
 }

rule lazaspy_android_rat {
	meta:
		source = "Facebook"
		date = "2022-08-04"
		description = "Custom Android RAT built on top of XploitSPY"
		reference = "https://about.fb.com/news/2022/08/metas-adversarial-threat-report-q2-2022/"
	strings:
		$s0 = "/.System/Ct.csv/"
		$s1 = "/.System/sm.csv/"
		$s2 = "logg.txt"
		$s3 = "ulog.txt"
		$s4 = "This Feature is currently Unavailable. Comming Soon!"
		$s5 = "Press Back Again to Exit."
		$s6 = "Please Grant Permission to Continue"
		$s7 = "Try Again something went wrong"
		$s8 = "Deleting Conversation Please wait"
		$s9 = "please type something"
		$s10 = "Message not Sent"
	condition:
		7 of ($s*) and xploitspy_rat
}
