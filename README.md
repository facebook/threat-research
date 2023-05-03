# Threat Detection Indicators
This repository contains indicators and methods for detecting malware and other malicious online activity. Indicators are listed here when our investigative teams strongly believe that they are tied to malicious activity. We recommend that all indicators listed in this repository be reviewed before taking action within your organization.

## Repository Structure
* `indicators` - Holds indicators in CSV, TSV, STIX v1, and JSON formats
* `signatures` - Hold detection signatures
	* `signatures/yara` - YARA (https://virustotal.github.io/yara/) signatures to detect malware and other files

## Schema
* `indicator_type` - References the type of indicator (e.g. `android_package_name`)
* `indicator_value` - The actual indicator
* `comment` - Any comments, very often the "name" of an app
* `ds` - Datestamp (yyyy-mm-dd) related to this indicator. Very often the date of publication not the date of detection

## Indicator Types
* `android_package_name` - An Android package name (e.g. com.example.app) _For STIX v1 this is placed within a File object in the "Filename" field_
* `ios_app_id` - An iOS App ID (e.g. 10000000001) _For STIX v1 this is placed within a File object in the "Filename" field_
* `domain_name` - A domain name
* `url` - A URL
* `md5` - An MD5 Hash
* `sha256` - A SHA256 Hash
* `ip` - An IP Address
* `phishing_url` - A URL associated with phishing
* `cib_url` - A URL associated with Coordinated Inauthentic Behavior (CIB)
* `telegram_url` - A URL to a Telegram Channel

## Index File Format
The file `index.json` can be used to programatically consume our indicators. The file is JSON formatted and contains an array of JSON objects, one for each "entry" in this repository. All paths in this file are relative to the root of the repo. The schema is as follows:

```json
{
	"id" : "id_of_the_entry",
	"added_ds" : "yyyy-mm-dd that this entry was added to the repo",
	"reported_ds" : "yyyy-mm-dd that this entry was first reported by Meta",
	"reference_urls" : ["Array of URLs where you can learn more"],
	"indicators" : {
		"csv_files" : ["paths to CSV files associated with this entry"],
		"json_files" : ["paths to JSON files associated with this entry"],
		"tsv_files" : ["paths to TSV files associated with this entry"],
		"stix1_files" : ["paths to XML STIX v1 files associated with this entry"],
		"stix2_files" : ["paths to JSON STIX v2 files associated with this entry"]
	},
	"signatures" : {
		"yara_files" : ["paths to YARA files associated with this entry"]
	}
}
```

## FAQ
### Why are you releasing this?
Please see https://about.fb.com/news/2022/10/protecting-people-from-malicious-account-compromise-apps/ to learn more

### How were these detected?
Meta uses a wide variety of techniques to find and combat malware and malicious activity. Exact detection methods are generally not shared publicly.

### How confident are you in these indicators?
We have high confidence in our indicators. We manually vet all indicators before they are published to this repository. There still remains a very low chance that an indicator may be a false positive, so we recommend users review the indicators before taking action.

### How can I report an issue?
Open an Issue on Github and we'll look into it

### How is this data licensed?
Under the MIT License (see `LICENSE`)

## Index of Filenames
* 2023_05_malware_iocs (csv, json, stix1, tsv) - https://about.fb.com/news/2023/05/how-meta-protects-businesses-from-malware/
* 2022_malicious_mobile_apps (csv, json, stix1, tsv) - https://about.fb.com/news/2022/10/protecting-people-from-malicious-account-compromise-apps/
* 2022_09_removing_coordinated_inauthentic_behavior_from_china_and_russia (csv, json, stix1, tsv) - https://about.fb.com/news/2022/09/removing-coordinated-inauthentic-behavior-from-china-and-russia/
* 2022_08_metas_adversarial_threat_report_q2 (csv, json, stix1, tsv, yara) - https://about.fb.com/news/2022/08/metas-adversarial-threat-report-q2-2022/
* 2022_04_metas_adversarial_threat_report_q1 (csv, json, stix1, tsv, yara) - https://about.fb.com/news/2022/04/metas-adversarial-threat-report-q1-2022/
* 2021_12_taking_action_against_surveillance_for_hire (csv, json, stix1, tsv) - https://about.fb.com/news/2021/12/taking-action-against-surveillance-for-hire/
* 2021_11_action_against_hackers_in_pakistan_and_syria (csv, json, stix1, tsv) - https://about.fb.com/news/2021/11/taking-action-against-hackers-in-pakistan-and-syria/
* 2021_07_taking_action_against_hackers_in_iran (csv, json, stix1, tsv) - https://about.fb.com/news/2021/07/taking-action-against-hackers-in-iran/
* 2021_04_taking_action_against_hackers_in_palestine (csv, json, stix1, tsv) - https://about.fb.com/news/2021/04/taking-action-against-hackers-in-palestine/
* 2021_03_taking_action_against_hackers_in_china (csv, json, stix1, tsv) - https://about.fb.com/news/2021/03/taking-action-against-hackers-in-china/
* 2020_12_taking_action_against_hackers_in_bangladesh_and_vietnam (csv, json, stix1, tsv, yara) - https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/
