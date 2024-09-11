package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Mesos docker Container Cluster Management Platform Unauthorized Access Vulnerability",
    "Description": "<p>Mesos_docker container cluster management platform is a distributed system solution based on Apache Mesos and Docker, which can help users quickly build and run large-scale containerized applications.</p><p>There are loopholes in this product, and attackers can control the entire system through unauthorized access loopholes, which ultimately leads to an extremely insecure state of the system.</p>",
    "Product": "APACHE-MESOS",
    "Homepage": "http://mesos.apache.org/",
    "DisclosureDate": "2017-06-20",
    "PostTime": "2023-08-03",
    "Author": "872554564@qq.com",
    "FofaQuery": "body=\"ng-app=\\\"mesos\\\"\" || body=\"/static/css/mesos.css\"",
    "GobyQuery": "body=\"ng-app=\\\"mesos\\\"\" || body=\"/static/css/mesos.css\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://mesos.apache.org/\">http://mesos.apache.org/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://0x0d.im/archives/attack-container-management-platform.html"
    ],
    "Is0day": false,
    "HasExp": false,
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
                "uri": "/version",
                "header": {},
                "data": "",
                "follow_redirect": false
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
                        "value": "\\w{40}",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Mesos docker 容器集群管理平台未授权访问漏洞",
            "Product": "APACHE-MESOS",
            "Description": "<p>Mesos_docker 容器集群管理平台是一种基于 Apache Mesos 和 Docker 的分布式系统解决方案，它可以帮助用户快速搭建和运行大规模的容器化应用。<br></p><p>该产品存在漏洞，攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。\t</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://mesos.apache.org/\">http://mesos.apache.org/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。\t<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Mesos docker Container Cluster Management Platform Unauthorized Access Vulnerability",
            "Product": "APACHE-MESOS",
            "Description": "<p>Mesos_docker container cluster management platform is a distributed system solution based on Apache Mesos and Docker, which can help users quickly build and run large-scale containerized applications.</p><p>There are loopholes in this product, and attackers can control the entire system through unauthorized access loopholes, which ultimately leads to an extremely insecure state of the system.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"http://mesos.apache.org/\">http://mesos.apache.org/</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "10810"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}