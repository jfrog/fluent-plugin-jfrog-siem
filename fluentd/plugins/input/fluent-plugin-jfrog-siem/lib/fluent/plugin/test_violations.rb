
def get_violations_details_test()
  response = '{
                    "violation_id": "1710136527020015616",
                    "description": "Root access could be granted to a stranger",
                    "summary": "Custom issue 1",
                    "severity": "High",
                    "type": "Security",
                    "provider": "MB",
                    "infected_components": [
                        "generic://sha256:242fe18ca64a362e4088096447c8f815fb2aa2c569c5f342de1c82318eb4973a/artifact_1.zip"
                    ],
                    "created": "2023-10-06T03:34:55Z",
                    "watch_name": "test_all-repositories_7005086_security",
                    "matched_policies": [
                        {
                            "policy": "test_security_policy_7005086",
                            "rule": "securityRule",
                            "is_blocking": false
                        }
                    ],
                    "issue_id": "XRAYS1-artifact_1.zip7005086",
                    "properties": [
                        {
                            "cve": "CVE-2018-2000568",
                            "cvss_v2": "5.0/CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:P/A:N"
                        }
                    ],
                    "impacted_artifacts": [
                        "mw-maven-repository-manager/inhouse_snapshot/com/mathworks/team/recruiting/recruiting/2.41.3-SNAPSHOT/recruiting-2.41.3-20230920.193355-4.war"
                    ],
                    "applicability": null
                }'
  resp_obj = JSON.parse(response)
  return resp_obj
end

def get_violations_test()
  response = '{
                  "total_violations":54,
                  "violations":[
                    {
                      "description":"Apache Software Foundation (ASF) Struts before 1.2.9 allows remote attackers to bypass validation via a request with a org.apache.struts.taglib.html.Constants.CANCEL parameter, which causes the action to be canceled but would not be detected from applications that do not use the isCancelled check.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.1"
                      ],
                      "created":"2021-06-16T21:22:18Z",
                      "watch_name":"maven-watch1",
                      "issue_id":"XRAY-55418",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=ff9cf61f42a095cd97ea0ec0&issue_id=XRAY-55418&comp_id=gav:%2F%2Fstruts:struts:1.1",
                      "impacted_artifacts":[
                        "mw-maven-repository-manager/inhouse_snapshot/com/mathworks/team/recruiting/recruiting/2.41.3-SNAPSHOT/recruiting-2.41.3-20230920.193355-4.war"
                      ]
                    },
                    {
                      "description":"The Apache Software License, Version 1.1",
                      "severity":"High",
                      "type":"License",
                      "infected_components":[
                        "gav://struts:struts:1.1"
                      ],
                      "created":"2021-06-16T21:22:18Z",
                      "watch_name":"license-watch",
                      "issue_id":"Apache-1.1",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=b241c1986818d68993093e35&issue_id=Apache-1.1&comp_id=gav:%2F%2Fstruts:struts:1.1",
                      "impacted_artifacts":[
                        "default/maven-repo-1/struts/struts/1.1/struts-1.1.jar"
                      ]
                    },
                    {
                      "description":"The MultiPageValidator implementation in Apache Struts 1 1.1 through 1.3.10 allows remote attackers to bypass intended access restrictions via a modified page parameter.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.1"
                      ],
                      "created":"2021-06-16T21:22:18Z",
                      "watch_name":"maven-watch1",
                      "issue_id":"XRAY-55648",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=ff9cf61f42a095cd97ea0ec0&issue_id=XRAY-55648&comp_id=gav:%2F%2Fstruts:struts:1.1",
                      "impacted_artifacts":[
                        "default/maven-repo-1/struts/struts/1.1/struts-1.1.jar"
                      ]
                    },
                    {
                      "description":"Cross-site scripting (XSS) vulnerability in Apache Struts before 1.2.9-162.31.1 on SUSE Linux Enterprise (SLE) 11, before 1.2.9-108.2 on SUSE openSUSE 10.3, before 1.2.9-198.2 on SUSE openSUSE 11.0, and before 1.2.9-162.163.2 on SUSE openSUSE 11.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors related to \"insufficient quoting of parameters.\"",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.1"
                      ],
                      "created":"2021-06-16T21:22:18Z",
                      "watch_name":"maven-watch1",
                      "issue_id":"XRAY-55444",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=ff9cf61f42a095cd97ea0ec0&issue_id=XRAY-55444&comp_id=gav:%2F%2Fstruts:struts:1.1",
                      "impacted_artifacts":[
                        "default/maven-repo-1/struts/struts/1.1/struts-1.1.jar"
                      ]
                    },
                    {
                      "description":"Cross-site scripting (XSS) vulnerability in (1) LookupDispatchAction and possibly (2) DispatchAction and (3) ActionDispatcher in Apache Software Foundation (ASF) Struts before 1.2.9 allows remote attackers to inject arbitrary web script or HTML via the parameter name, which is not filtered in the resulting error message.",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.1"
                      ],
                      "created":"2021-06-16T21:22:18Z",
                      "watch_name":"maven-watch1",
                      "issue_id":"XRAY-55420",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=ff9cf61f42a095cd97ea0ec0&issue_id=XRAY-55420&comp_id=gav:%2F%2Fstruts:struts:1.1",
                      "impacted_artifacts":[
                        "default/maven-repo-1/struts/struts/1.1/struts-1.1.jar"
                      ]
                    },
                    {
                      "description":"ActionForm in Apache Software Foundation (ASF) Struts before 1.2.9 with BeanUtils 1.7 allows remote attackers to cause a denial of service via a multipart/form-data encoded form with a parameter name that references the public getMultipartRequestHandler method, which provides further access to elements in the CommonsMultipartRequestHandler implementation and BeanUtils.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.1"
                      ],
                      "created":"2021-06-16T21:22:18Z",
                      "watch_name":"maven-watch1",
                      "issue_id":"XRAY-55419",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=ff9cf61f42a095cd97ea0ec0&issue_id=XRAY-55419&comp_id=gav:%2F%2Fstruts:struts:1.1",
                      "impacted_artifacts":[
                        "default/maven-repo-1/struts/struts/1.1/struts-1.1.jar"
                      ]
                    },
                    {
                      "description":"The MultiPageValidator implementation in Apache Struts 1 1.1 through 1.3.10 allows remote attackers to bypass intended access restrictions via a modified page parameter.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.2.4"
                      ],
                      "created":"2021-06-16T21:22:27Z",
                      "watch_name":"maven-watch-2",
                      "issue_id":"XRAY-55648",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2a3ee020bf1a86b84d122c0c&issue_id=XRAY-55648&comp_id=gav:%2F%2Fstruts:struts:1.2.4",
                      "impacted_artifacts":[
                        "default/maven-repo-2/struts/struts/1.2.4/struts-1.2.4.jar"
                      ]
                    },
                    {
                      "description":"ActionForm in Apache Software Foundation (ASF) Struts before 1.2.9 with BeanUtils 1.7 allows remote attackers to cause a denial of service via a multipart/form-data encoded form with a parameter name that references the public getMultipartRequestHandler method, which provides further access to elements in the CommonsMultipartRequestHandler implementation and BeanUtils.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.2.4"
                      ],
                      "created":"2021-06-16T21:22:27Z",
                      "watch_name":"maven-watch-2",
                      "issue_id":"XRAY-55419",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2a3ee020bf1a86b84d122c0c&issue_id=XRAY-55419&comp_id=gav:%2F%2Fstruts:struts:1.2.4",
                      "impacted_artifacts":[
                        "default/maven-repo-2/struts/struts/1.2.4/struts-1.2.4.jar"
                      ]
                    },
                    {
                      "description":"Cross-site scripting (XSS) vulnerability in (1) LookupDispatchAction and possibly (2) DispatchAction and (3) ActionDispatcher in Apache Software Foundation (ASF) Struts before 1.2.9 allows remote attackers to inject arbitrary web script or HTML via the parameter name, which is not filtered in the resulting error message.",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.2.4"
                      ],
                      "created":"2021-06-16T21:22:27Z",
                      "watch_name":"maven-watch-2",
                      "issue_id":"XRAY-55420",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2a3ee020bf1a86b84d122c0c&issue_id=XRAY-55420&comp_id=gav:%2F%2Fstruts:struts:1.2.4",
                      "impacted_artifacts":[
                        "default/maven-repo-2/struts/struts/1.2.4/struts-1.2.4.jar"
                      ]
                    },
                    {
                      "description":"The Apache Software License, Version 2.0",
                      "severity":"High",
                      "type":"License",
                      "infected_components":[
                        "gav://struts:struts:1.2.4"
                      ],
                      "created":"2021-06-16T21:22:27Z",
                      "watch_name":"license-watch",
                      "issue_id":"Apache-2.0",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=b241c1986818d68993093e35&issue_id=Apache-2.0&comp_id=gav:%2F%2Fstruts:struts:1.2.4",
                      "impacted_artifacts":[
                        "default/maven-repo-2/struts/struts/1.2.4/struts-1.2.4.jar"
                      ]
                    },
                    {
                      "description":"Cross-site scripting (XSS) vulnerability in Apache Struts before 1.2.9-162.31.1 on SUSE Linux Enterprise (SLE) 11, before 1.2.9-108.2 on SUSE openSUSE 10.3, before 1.2.9-198.2 on SUSE openSUSE 11.0, and before 1.2.9-162.163.2 on SUSE openSUSE 11.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors related to \"insufficient quoting of parameters.\"",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.2.4"
                      ],
                      "created":"2021-06-16T21:22:27Z",
                      "watch_name":"maven-watch-2",
                      "issue_id":"XRAY-55444",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2a3ee020bf1a86b84d122c0c&issue_id=XRAY-55444&comp_id=gav:%2F%2Fstruts:struts:1.2.4",
                      "impacted_artifacts":[
                        "default/maven-repo-2/struts/struts/1.2.4/struts-1.2.4.jar"
                      ]
                    },
                    {
                      "description":"Apache Software Foundation (ASF) Struts before 1.2.9 allows remote attackers to bypass validation via a request with a org.apache.struts.taglib.html.Constants.CANCEL parameter, which causes the action to be canceled but would not be detected from applications that do not use the isCancelled check.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://struts:struts:1.2.4"
                      ],
                      "created":"2021-06-16T21:22:27Z",
                      "watch_name":"maven-watch-2",
                      "issue_id":"XRAY-55418",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2a3ee020bf1a86b84d122c0c&issue_id=XRAY-55418&comp_id=gav:%2F%2Fstruts:struts:1.2.4",
                      "impacted_artifacts":[
                        "default/maven-repo-2/struts/struts/1.2.4/struts-1.2.4.jar"
                      ]
                    },
                    {
                      "description":"Unicode Terms of Use",
                      "severity":"High",
                      "type":"License",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:37Z",
                      "watch_name":"license-watch",
                      "issue_id":"Unicode-TOU",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=b241c1986818d68993093e35&issue_id=Unicode-TOU&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"BSD 3-Clause \"New\" or \"Revised\" License",
                      "severity":"High",
                      "type":"License",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:37Z",
                      "watch_name":"license-watch",
                      "issue_id":"BSD-3-Clause",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=b241c1986818d68993093e35&issue_id=BSD-3-Clause&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"The Apache Software License, Version 2.0",
                      "severity":"High",
                      "type":"License",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:37Z",
                      "watch_name":"license-watch",
                      "issue_id":"Apache-2.0",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=b241c1986818d68993093e35&issue_id=Apache-2.0&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"The OGNL extensive expression evaluation capability in XWork in Struts 2.0.0 through 2.1.8.1, as used in Atlassian Fisheye, Crucible, and possibly other products, uses a permissive whitelist, which allows remote attackers to modify server-side context objects and bypass the \"#\" protection mechanism in ParameterInterceptors via the (1) #context, (2) #_memberAccess, (3) #root, (4) #this, (5) #_typeResolver, (6) #_classResolver, (7) #_traceEvaluations, (8) #_lastEvaluation, (9) #_keepLastEvaluation, and possibly other OGNL context variables, a different vulnerability than CVE-2008-6504.",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:37Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-55471",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-55471&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Academic Free License v2.1",
                      "severity":"High",
                      "type":"License",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:37Z",
                      "watch_name":"license-watch",
                      "issue_id":"AFL-2.1",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=b241c1986818d68993093e35&issue_id=AFL-2.1&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"ParametersInterceptor in OpenSymphony XWork 2.0.x before 2.0.6 and 2.1.x before 2.1.2, as used in Apache Struts and other products, does not properly restrict # (pound sign) references to context objects, which allows remote attackers to execute Object-Graph Navigation Language (OGNL) statements and modify server-side context objects, as demonstrated by use of a \\u0023 representation for the # character.",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-55446",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-55446&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Multiple cross-site scripting (XSS) vulnerabilities in Apache Struts 2.0.x before 2.0.11.1 and 2.1.x before 2.1.1 allow remote attackers to inject arbitrary web script or HTML via vectors associated with improper handling of (1) \" (double quote) characters in the href attribute of an s:a tag and (2) parameters in the action attribute of an s:url tag.",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-55448",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-55448&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.",
                      "severity":"Critical",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-129844",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-129844&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"The ExceptionDelegator component in Apache Struts before 2.2.3.1 interprets parameter values as OGNL expressions during certain exception handling for mismatched data types of properties, which allows remote attackers to execute arbitrary Java code via a crafted parameter.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-55522",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-55522&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Apache Struts 2 before 2.3.14.3 allows remote attackers to execute arbitrary OGNL code via a request with a crafted value that contains both \"${}\" and \"%{}\" sequences, which causes the OGNL code to be evaluated twice.",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-55575",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-55575&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Apache Struts JSP Page Handling Unspecified XSS",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-81164",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-81164&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Apache Struts <s:textfield> Tag <s:include> Handling XSS",
                      "severity":"Medium",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-81187",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-81187&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    },
                    {
                      "description":"Apache Struts EL / OGNL Interpretation Unspecified Remote Code Execution",
                      "severity":"High",
                      "type":"Security",
                      "infected_components":[
                        "gav://org.apache.struts:struts2-core:2.0.9"
                      ],
                      "created":"2021-06-16T21:22:38Z",
                      "watch_name":"maven-watch-3",
                      "issue_id":"XRAY-87424",
                      "violation_details_url":"http://localhost:8046/xray/api/v1/violations?watch_id=2c5ecab8172f24086f4b3bf4&issue_id=XRAY-87424&comp_id=gav:%2F%2Forg.apache.struts:struts2-core:2.0.9",
                      "impacted_artifacts":[
                        "default/maven-repo-3/org/apache/struts/struts2-core/2.0.9/struts2-core-2.0.9.jar"
                      ]
                    }
                  ]
                }'
  resp_obj = JSON.parse(response)
  return resp_obj
end