FROM bitnami/fluentd:1.12.3
LABEL maintainer "JFrog <partner-support@jfrog.com>"

## requires to be root to install fluentd plugins
USER root

RUN chown -R 1001:1001 /opt/bitnami/fluentd

USER 1001

RUN fluent-gem install fluent-plugin-jfrog-siem