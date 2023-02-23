# JFrog Fluentd SIEM Input Plugin Changelog
All changes to the SIEM plugin will be documented in this file.

## [2.0.6]
* Adding additional logs for better visibility into issues

## [2.0.5]
* Fixing concurrent-ruby version to lesst than 1.1.10 for timer task dependency

## [2.0.1] - August 25, 2021
* Pointing documentation to correct repo
* Changing contributors

## [2.0.0] - August 16, 2021
* [BREAKING] Changes to config (pos_file_path, from_date)
* Adding concurrent-ruby dependency

## [1.0.0] - May 18, 2021
* [BREAKING] Using JFrog API Key for authentication

## [0.1.9] - May 17, 2021
* Handling the case where violations are left in a batch to be processed

## [0.1.8] - May 10, 2021
* Fixing persist, not persist item conditions

## [0.1.7] - April 21, 2021
* Adding policies and rules to payload

## [0.1.6] - April 13, 2021
* Adding additonal parameters to match with access logs for correlation

## [0.1.5] - March 29, 2021
* Normalizing the format of Impacted Artifact, fixing properties not found case

## [0.1.4] - February 02, 2021
* Adding dependencies, gemspec updates

## [0.1.3] - January 21, 2021
* Fixing thread pool issues (moving loop inside a thread pool)

## [0.1.2] - November 17, 2020
* Changes to better README

## [0.1.1] - November 17, 2020
* Adding dependencies to gemspec

## [0.1.0] - October 05, 2020
* Initial release of Jfrog Logs Analytic integration

