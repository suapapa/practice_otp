package main

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	otpCache    = map[string]string{}
	tokenSecret = []byte("secret") // TODO: change to env

	indexTmpl *template.Template
)

func init() {
	var err error
	indexTmpl, err = template.ParseGlob("template/*.html")
	if err != nil {
		log.Fatalf("template.ParseGlob: %v", err)
	}
}

func main() {
	r := gin.New()
	// add middleware
	r.Use(gin.Logger())

	r.GET("/login", loginHandler)
	r.GET("/generate-otp", generateOTPHandler)
	r.GET("/submit-otp", submitOTPHandler)
	r.GET("/hello", authMiddleWare, helloHandler)

	r.Run(":8080")
}

func loginHandler(c *gin.Context) {
	c.Header("cess-Control-Allow-Origin", "*")
	err := indexTmpl.ExecuteTemplate(c.Writer, "index.html", c.Request.URL.Hostname())
	if err != nil {
		c.JSON(500, gin.H{
			"message": "Internal Server Error",
		})
		return
	}
}

func GeneratePassCode(secret string) string {
	// secret = base32.StdEncoding.EncodeToString([]byte(secret))
	passcode, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
	return passcode
}

func generateOTPHandler(c *gin.Context) {
	email := c.Query("email")
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "homin.dev",
		AccountName: email,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		c.JSON(500, gin.H{
			"message": "Internal Server Error",
		})
		return
	}

	// TODO: send key.Secret to homin.dev
	log.Printf("key.Secret: %v", key.Secret())
	otpCache[email] = key.Secret()
	time.Sleep(time.Second)
	passCode := GeneratePassCode(key.Secret())
	log.Printf("passCode: %v", passCode)
	time.Sleep(time.Second)

	c.JSON(200, gin.H{
		"message": "OK",
	})
}

func submitOTPHandler(c *gin.Context) {
	email := c.Query("email")
	otp := c.Query("otp")
	if secret, ok := otpCache[email]; ok && totp.Validate(otp, secret) {
		// generate JWT token
		token, err := createToken(email)
		if err != nil {
			c.JSON(500, gin.H{
				"message": "Internal Server Error",
			})
			return
		}

		// save JWT token to cookie
		c.SetCookie("token", token, 3600, "/", c.Request.URL.Hostname(), false, true)
		c.JSON(200, gin.H{
			"message": "OK",
		})
		return
	}

	location := url.URL{Path: "/login"}
	c.Redirect(http.StatusFound, location.RequestURI())
}

func helloHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Hello World",
	})
}

func authMiddleWare(c *gin.Context) {
	if cookie, err := c.Cookie("token"); err != nil || cookie == "" {
		goto unauthorized
	} else {
		token, err := jwt.Parse(cookie, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, err
			}
			return tokenSecret, nil
		})
		if err != nil {
			goto unauthorized
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			log.Printf("claims: %v", claims)
			// TODO: check timeout in claims

			c.Next()
			return
		}
	}

unauthorized:
	location := url.URL{Path: "/login"}
	c.Redirect(http.StatusFound, location.RequestURI())
	c.Abort()
	return
}

// ---

func createToken(email string) (string, error) {
	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["email"] = email
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString(tokenSecret)
	if err != nil {
		return "", err
	}
	return token, nil
}
