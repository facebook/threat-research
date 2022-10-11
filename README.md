# Malware Detection Indicators
This repository contains indicators and methods for detecting malware. Indicators are listed here when our malware teams strongly believe that they are tied to malicious activity. We recommend that all indicators listed in this repository be reviewed before taking action within your organization.

## Repository Structure
* `indicators` - Holds indicators in CSV, TSV, and JSON formats

## Schema
* `indicator_type` - References the type of indicator (e.g. `android_package_name`)
* `indicator_value` - The actual indicator
* `comment` - Any comments, very often the "name" of an app
* `ds` - Datestamp (yyyy-mm-dd) related to this indicator. Very often the date of publication not the date of detection

## Indicator Types
* `android_package_name` - An Android package name (e.g. com.example.app)
* `ios_app_id` - An iOS App ID (e.g. 10000000001)
* `domain_name` - A domain name
* `md5` - An MD5 Hash
* `ip` - An IP Address
* `cib_url` - A URL associated with Coordinated Inauthentic Behavior (CIB)
* `telegram_url` - A URL to a Telegram Channel

## FAQ
### Why are you releasing this?
Please see https://about.fb.com/news/2022/10/protecting-people-from-malicious-account-compromise-apps/ to learn more

### How were these detected?
Meta uses a wide variety of techniques to find and combat malware. Exact detection methods are generally not shared publicly.

### How confident are you in these indicators?
We have high confidence in our indicators. We manually vet all indicators before they are published to this repository. There still remains a very low chance that an indicator may be a false positive, so we recommend users review the indicators before taking action.

### How can I report an issue?
Open an Issue on Github and we'll look into it

### How is this data licensed?
Under the MIT License (see `LICENSE`)

## Index of Filenames
* 2022_malicious_mobile_apps - https://about.fb.com/news/2022/10/protecting-people-from-malicious-account-compromise-apps/
* 2022_09_removing_coordinated_inauthentic_behavior_from_china_and_russia - https://about.fb.com/news/2022/09/removing-coordinated-inauthentic-behavior-from-china-and-russia/
* 2021_11_action_against_hackers_in_pakistan_and_syria - https://about.fb.com/news/2021/11/taking-action-against-hackers-in-pakistan-and-syria/
* 2021_07_taking_action_against_hackers_in_iran - https://about.fb.com/news/2021/07/taking-action-against-hackers-in-iran/
