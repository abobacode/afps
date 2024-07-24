package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/abobacode/afps/config"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/abobacode/afps/ksm"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/urfave/cli/v2"
)

type SpcMessage struct {
	Spc     string `json:"spc" binding:"required"`
	AssetID string `json:"assetID"`
}

type ErrorMessage struct {
	Status  int    `json:"status" binding:"required"`
	Message string `json:"message" binding:"required"`
}

type CkcResult struct {
	Ckc string `json:"ckc" binding:"required"`
}

//var FairplayPrivateKey = ReadPriKey()
//var FairplayPublicCertification = ReadPublicCert()
//var FairplayASk = ReadASk()

func main() {
	application := cli.App{
		Name: "FairPlay KSM Service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config-file",
				Required: true,
				Usage:    "YAML config filepath",
				EnvVars:  []string{"CONFIG_FILE"},
				FilePath: "/srv/lime_secrets/config_file",
			},
		},
		Action: Main,
	}

	if err := application.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func Main(ctx *cli.Context) error {
	cfg, err := config.New(ctx.String("config-file"))
	if err != nil {
		return err
	}

	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"}, // FIXME: Use your streaming domain.
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPost},
	}))

	k := &ksm.Ksm{
		Pub: ReadPublicCert(cfg),
		Pri: ReadPriKey(cfg),
		Rck: ksm.RandomContentKey{}, //NOTE: Don't use ramdom key in your application.
		Ask: ReadASk(cfg),
	}

	e.GET("/", func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "OK")
	})
	e.POST("/fps/license", func(ctx echo.Context) error {
		spcMessage := new(SpcMessage)
		var playback []byte
		var base64EncodingMethod string
		contentType := ctx.Request().Header.Get("Content-Type")

		if err := ctx.Bind(spcMessage); err != nil {
			errorMessage := &ErrorMessage{Status: 400, Message: err.Error()}
			fmt.Println(ctx.Request().Header)
			fmt.Println(ctx.Request().Body)
			return ctx.JSON(http.StatusBadRequest, errorMessage)
		}

		if strings.Contains(spcMessage.Spc, "-") || strings.Contains(spcMessage.Spc, "_") {
			base64EncodingMethod = "URL"
			decoded, err := base64.URLEncoding.DecodeString(spcMessage.Spc)
			if err != nil {
				panic(err)
			}
			playback = decoded
		} else if strings.Contains(spcMessage.Spc, " ") && strings.Contains(spcMessage.Spc, "/") {
			base64EncodingMethod = "STD"
			decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(spcMessage.Spc, " ", "+"))
			if err != nil {
				panic(err)
			}
			playback = decoded
		} else {
			base64EncodingMethod = "STD"
			decoded, err := base64.StdEncoding.DecodeString(spcMessage.Spc)
			if err != nil {
				panic(err)
			}
			playback = decoded
		}

		ckc, err := k.GenCKC(playback)
		if err != nil {
			panic(err)
		}

		var result string

		switch base64EncodingMethod {
		case "URL":
			result = base64.URLEncoding.EncodeToString(ckc)
		case "STD":
			result = base64.StdEncoding.EncodeToString(ckc)
		default:
			result = base64.StdEncoding.EncodeToString(ckc)
		}

		fmt.Println(result)

		switch contentType {
		case "application/json":
			return ctx.JSON(200, &CkcResult{Ckc: result})
		case "application/x-www-form-urlencoded":
			return ctx.Blob(200, "application/x-www-form-urlencoded", []byte("<ckc>"+result+"</ckc>"))
		default:
			return ctx.Blob(200, "application/x-www-form-urlencoded", []byte("<ckc>"+result+"</ckc>"))
		}
	})
	e.Logger.Fatal(e.Start(":8080"))

	return nil
}

func ReadPublicCert(cfg *config.Config) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(cfg.Server.FairPlay.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse certificate: ", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("not an RSA public key")
	}
	return pubKey
}

func ReadPriKey(cfg *config.Config) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(cfg.FairPlay.Private))
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatal("failed to decode PEM block containing the private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse private key: ", err)
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("not an RSA private key")
	}
	return rsaPrivKey
}

func ReadASk(cfg *config.Config) []byte {
	askEnvVar := cfg.FairPlay.Ask
	ask, err := hex.DecodeString(askEnvVar)
	if err != nil {
		panic(err)
	}
	return ask
}
