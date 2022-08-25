# Malware Detection Indicators
This repository contains indicators and methods for detecting malware. Indicators are listed here when our malware teams strongly believe that they are tied to malicious activity. We recommend that all indicators listed in this repository be reviewed before taking action within your organization.

## FAQ
### How were these detected?
Meta uses a wide variety of techniques to find and combat malware. Exact detection methods are generally not shared publicly.

### How confident are you in these indicators?
We have high confidence in our indicators. We manually vet all indicators before they are published to this repository. There still remains a very low chance that an indicator may be a false positive, so we recommend users review the indicators before taking action.

## Repository Structure
* indicators - Holds indicators in CSV, TSV, and JSON formats

## Schema
* `indicator_type` - References the type of indicator (e.g. `android_package_name`)
* `indicator_value` - The actual indicator
* `comment` - Any comments, very often the "name" of an app
* `ds` - Datestamp (yyyy-mm-dd) related to this indicator. Very often the date of publication not the date of detection

## Indicator Types
* `android_package_name` - An Android package name (e.g. com.example.app)
* `ios_app_id` - An iOS App ID (e.g. 10000000001)
