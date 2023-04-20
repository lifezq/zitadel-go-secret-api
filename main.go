/**
* PACKAGE main
* Name main
* Description ZITADEL integrate with golang
* Author Ryan
* Date 2023/4/20
 */
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

const (
	ZITADEL_ISSUER                   = "https://dpi-6v6cya.zitadel.cloud"
	ZITADEL_CLIENT_ID                = "206333304817910017@spring_boot"
	ZITADEL_CLIENT_SECRET            = "C8llspq7Ywp8KTi6iaSkOlsjbTMk54kqzwg7ogjxpuBrQz2totZ0xvTQHRplUly3"
	ZITADEL_REDIRECT_URL             = "http://localhost:8080/api/login/callback"
	ZITADEL_SCOPES                   = "openid%20email%20profile"
	ZITADEL_POST_LOGOUT_REDIRECT_URI = "http://localhost:8080/api/login"
)

var (
	ZITADEL_LOGIN_URL = fmt.Sprintf("%s/oauth/v2/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=%s", ZITADEL_ISSUER, ZITADEL_CLIENT_ID, ZITADEL_REDIRECT_URL, ZITADEL_SCOPES)
)

var (
	port = flag.Int("port", 8080, "server port")
)

func main() {

	flag.Parse()

	// 建立redis连接，主要用于多服务端应用会话信息同步
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	if rdb == nil {
		panic("redis连接失败")
	}

	defer rdb.Close()

	// 创建一个 Gin 引擎实例
	r := gin.Default()

	// 添加中间件
	authMiddleware := NewGinAuthMiddleware()
	r.Use(authMiddleware)

	// 定义一个路由组
	api := r.Group("/api")

	// 限制只有具有 "admin" 角色的用户才能访问 /api/admin
	admin := api.Group("/admin")
	admin.Use(RoleMiddleware("admin"))
	admin.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, admin!"})
	})

	// 限制只有具有 "user" 角色的用户才能访问 /api/user
	user := api.Group("/user")
	user.Use(RoleMiddleware("user"))
	user.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, user!"})
	})

	userinfo := api.Group("/userinfo")
	userinfo.GET("/", func(c *gin.Context) {
		cookie, err := c.Cookie("Authorization")
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，未获取到身份信息!"})
			return
		}

		httpClient := &http.Client{}
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/oidc/v1/userinfo",
			ZITADEL_ISSUER), nil)
		req.Header.Set("Authorization", "Bearer "+cookie)
		resp, err := httpClient.Do(req)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，获取数据失败!"})
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，加载数据失败!"})
			return
		}

		var data oidc.UserInfo
		err = json.Unmarshal(body, &data)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，解析数据失败!"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": data})
	})

	login := api.Group("/login")
	login.GET("/", func(c *gin.Context) {
		introspectResponse, _ := introspect(c.Request)
		if introspectResponse != nil {
			c.Redirect(302, fmt.Sprintf("%s&login_hint=%s",
				ZITADEL_LOGIN_URL, introspectResponse.PreferredUsername))
		}

		c.Redirect(302, ZITADEL_LOGIN_URL)
	})
	login.GET("/callback", func(c *gin.Context) {
		code := strings.Trim(c.Query("code"), " ")
		if len(code) > 0 {
			// get code success
			// get access token by code
			tokenUrl := fmt.Sprintf("%s/oauth/v2/token?code=%s&grant_type=authorization_code&redirect_uri=%s",
				ZITADEL_ISSUER, code, ZITADEL_REDIRECT_URL)

			v := url.Values{}
			v.Set("code", code)
			v.Set("grant_type", "authorization_code")
			v.Set("redirect_uri", ZITADEL_REDIRECT_URL)
			v.Set("client_id", ZITADEL_CLIENT_ID)
			v.Set("client_secret", ZITADEL_CLIENT_SECRET)

			fmt.Printf("do token request url:%s\n", tokenUrl)
			resp, err := http.Post(tokenUrl, "application/x-www-form-urlencoded", bytes.NewReader([]byte(v.Encode())))
			if resp == nil || err != nil {
				c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，未获取到身份信息!"})
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，加载数据错误!"})
				return
			}

			token := &oidc.AccessTokenResponse{}
			err = json.Unmarshal(body, token)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，解析数据错误!"})
				return
			}

			cookie := &http.Cookie{
				Name:     "Authorization",
				Value:    token.AccessToken,
				Path:     "/",
				Domain:   c.Request.Host,
				MaxAge:   int(token.ExpiresIn),
				HttpOnly: false,
			}

			http.SetCookie(c.Writer, cookie)

			username := ""
			ns := strings.Split(token.IDToken, ".")
			if len(ns) == 3 {
				tokenPayload, _ := base64.RawStdEncoding.DecodeString(ns[1])
				tokenPayloadmap := map[string]interface{}{}
				json.Unmarshal(tokenPayload, &tokenPayloadmap)

				if tokenPayloadmap["preferred_username"] != nil {
					username = tokenPayloadmap["preferred_username"].(string)
				}
			}

			if username == "" {
				c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，获取用户失败!"})
				return
			}

			err = rdb.Set(c, token.AccessToken, string(body), 0).Err()
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"message": "请求失败，保存会话信息失败!"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "登录成功，欢迎用户《" + username + "》"})
		} else {
			c.Redirect(302, ZITADEL_LOGIN_URL)
		}
	})

	login.GET("/check", func(c *gin.Context) {
		introspectResponse, err := introspect(c.Request)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "校验成功，用户《" + introspectResponse.PreferredUsername + "》已登录"})
	})

	logout := api.Group("/logout")
	logout.GET("/", func(c *gin.Context) {
		accessToken, err := c.Cookie("Authorization")
		if err != nil || accessToken == "" {
			c.JSON(http.StatusForbidden, gin.H{"message": "校验失败，未获取到身份信息"})
			return
		}

		value, err := rdb.Get(c, accessToken).Result()
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "无效的会话信息"})
			return
		}

		var token oidc.AccessTokenResponse
		err = json.Unmarshal([]byte(value), &token)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"message": "解析会话数据失败"})
			return
		}

		cookie := &http.Cookie{
			Name:     "Authorization",
			Value:    token.AccessToken,
			Path:     "/",
			Domain:   c.Request.Host,
			MaxAge:   -1,
			HttpOnly: false,
		}

		http.SetCookie(c.Writer, cookie)

		rdb.Del(c, token.AccessToken)

		c.Redirect(302, fmt.Sprintf("%s/oidc/v1/end_session?id_token_hint=%s&client_id=%s&post_logout_redirect_uri=%s",
			ZITADEL_ISSUER, token.IDToken, ZITADEL_CLIENT_ID, ZITADEL_POST_LOGOUT_REDIRECT_URI))
	})

	// 启动服务器
	if err := r.Run(fmt.Sprintf(":%d", *port)); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func introspect(request *http.Request) (*oidc.IntrospectionResponse, error) {
	cookie, err := request.Cookie("Authorization")
	if err != nil || cookie.Value == "" {
		return nil, errors.New("校验失败，未获取到身份信息")
	}

	v := url.Values{}
	v.Set("token", cookie.Value)
	cc := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/oauth/v2/introspect", ZITADEL_ISSUER),
		bytes.NewReader([]byte(v.Encode())))
	if err != nil {
		return nil, errors.New("校验失败，请求建立失败")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", basicAuthHeaderGenerate())

	resp, err := cc.Do(req)
	if err != nil {
		return nil, errors.New("校验失败，请求执行失败")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("校验失败，加载数据错误")
	}

	var introspectResponse oidc.IntrospectionResponse
	err = json.Unmarshal(body, &introspectResponse)
	if err != nil {
		return nil, errors.New("校验失败，解析数据错误")
	}

	if !introspectResponse.Active {
		return nil, errors.New("校验失败，令牌无效")
	}

	return &introspectResponse, nil
}

func basicAuthHeaderGenerate() string {
	return fmt.Sprintf("Basic %s", base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s",
		url.QueryEscape(ZITADEL_CLIENT_ID), url.QueryEscape(ZITADEL_CLIENT_SECRET)))))
}

// NewGinAuthMiddleware 创建一个 Gin 中间件，用于检查用户是否已经登录，并把用户信息存储到上下文中
func NewGinAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		if strings.HasPrefix(c.Request.RequestURI, "/api/login") {
			c.Next()
			return
		}

		instropectResponse, err := introspect(c.Request)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		roles, ok := instropectResponse.Claims["urn:zitadel:iam:org:project:roles"]
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		roleObjects := make(map[string]any)
		switch roles.(type) {
		case map[string]any:
			roleObjects = roles.(map[string]any)
		default:
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// 把用户信息存储到上下文中，以便后续的处理函数使用
		c.Set("roles", roleObjects)

		// 调用下一个处理函数
		c.Next()
	}
}

// RoleMiddleware 创建一个 Gin 中间件，用于检查用户是否具有指定角色
func RoleMiddleware(role string) gin.HandlerFunc {
	return func(c *gin.Context) {

		roles, ok := c.Get("roles")
		if !ok {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		pass := false
		for r, _ := range roles.(map[string]any) {
			if r == role {
				pass = true
				break
			}
		}

		if !pass {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// 调用下一个处理函数
		c.Next()
	}
}
