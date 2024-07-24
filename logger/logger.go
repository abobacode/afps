package logger

import (
	"fmt"
	"log"
	"os"
)

var logger *log.Logger

func init() {
	logger = log.New(os.Stdout, "", 0)
}

func Println(args ...interface{}) {
	logger.Println(args...)
}

func Printf(format string, args ...interface{}) {
	logger.Println(fmt.Sprintf(format, args...))
}

func SetLogger(l *log.Logger) {
	logger = l
}
