# JFrog's Xray SIEM plugin

A plugin to observe all the vulnerabilities associated with your artifacts. This plugin integrates with JFrog Xray and streams the security violations detected by Xray to the dashboard integration of your choice. You will need the supported version of fluentd installed, this plugin, the APIKey to access your instance of JFrog Platform and the API Key to connect to your dashboard for streaming logs(Datadog, Splunk, ElasticSearch)

## Install

Once you install this plugin and start fluentd you will be able to see the violations being streamed to your chosen dashboard.

You can install this plugin in a container using the [Dockerfile](Dockerfile) in this repository

If you are looking for a Kubernetes based installation you can find the helm chart

## Contributing
Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests to us.
## Versioning
We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).
